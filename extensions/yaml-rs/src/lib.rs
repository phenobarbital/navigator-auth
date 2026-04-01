/// yaml-rs: Fast YAML serialization/deserialization using Rust + PyO3
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use pyo3::IntoPyObject;
use serde_json;
use serde_yaml;

/// Convert Python object to YAML string
#[pyfunction]
fn dumps(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<String> {
    let json_value = python_to_json(py, obj)?;
    serde_yaml::to_string(&json_value).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "YAML serialization error: {}",
            e
        ))
    })
}

/// Convert Python object to YAML with custom formatting
#[pyfunction]
#[pyo3(signature = (obj, indent=2, flow_style=false, sort_keys=false))]
fn dumps_formatted(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    indent: usize,
    flow_style: bool,
    sort_keys: bool,
) -> PyResult<String> {
    if flow_style {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "flow_style formatting is not supported by serde_yaml",
        ));
    }

    let mut json_value = python_to_json(py, obj)?;

    if sort_keys {
        sort_json_value(&mut json_value);
    }

    let yaml_string = serde_yaml::to_string(&json_value).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "YAML serialization error: {}",
            e
        ))
    })?;

    if indent == 2 {
        Ok(yaml_string)
    } else {
        Ok(adjust_yaml_indent(&yaml_string, indent))
    }
}

/// Convert YAML string to Python object
#[pyfunction]
fn loads(py: Python<'_>, yaml_str: &str) -> PyResult<PyObject> {
    let value: serde_json::Value = serde_yaml::from_str(yaml_str).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("YAML parse error: {}", e))
    })?;
    json_to_python(py, &value)
}

/// Convert Python object to JSON Value (using Bound API)
fn python_to_json(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if obj.is_none() {
        Ok(serde_json::Value::Null)
    } else if obj.is_instance_of::<PyBool>() {
        let b: bool = obj.extract()?;
        Ok(serde_json::Value::Bool(b))
    } else if obj.is_instance_of::<PyInt>() {
        let i: i64 = obj.extract()?;
        Ok(serde_json::Value::Number(i.into()))
    } else if obj.is_instance_of::<PyFloat>() {
        let f: f64 = obj.extract()?;
        if let Some(num) = serde_json::Number::from_f64(f) {
            Ok(serde_json::Value::Number(num))
        } else {
            Ok(serde_json::Value::Null)
        }
    } else if obj.is_instance_of::<PyString>() {
        let s: String = obj.extract()?;
        Ok(serde_json::Value::String(s))
    } else if let Ok(list) = obj.downcast::<PyList>() {
        let mut vec = Vec::new();
        for item in list.iter() {
            vec.push(python_to_json(py, &item)?);
        }
        Ok(serde_json::Value::Array(vec))
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (key, value) in dict.iter() {
            let key_str: String = key.extract()?;
            map.insert(key_str, python_to_json(py, &value)?);
        }
        Ok(serde_json::Value::Object(map))
    } else if obj.hasattr("model_dump")? {
        // Handle Pydantic BaseModel
        let dict = obj.call_method0("model_dump")?;
        python_to_json(py, &dict)
    } else if obj.hasattr("__dataclass_fields__")? {
        // Handle dataclass objects
        let dataclasses = py.import("dataclasses")?;
        let asdict = dataclasses.getattr("asdict")?;
        let dict = asdict.call1((obj,))?;
        python_to_json(py, &dict)
    } else if obj.hasattr("dict")? {
        // Handle objects with .dict attribute
        let dict = obj.getattr("dict")?;
        python_to_json(py, &dict)
    } else {
        // Fallback to string representation
        let s: String = obj.str()?.extract()?;
        Ok(serde_json::Value::String(s))
    }
}

/// Convert JSON Value to Python object (using Bound API)
fn json_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok((*b).into_pyobject(py).unwrap().to_owned().into_any().unbind()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(py.None())
            }
        }
        serde_json::Value::String(s) => Ok(s.into_pyobject(py)?.into_any().unbind()),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_to_python(py, item)?)?;
            }
            Ok(list.unbind().into())
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, value) in map {
                dict.set_item(key, json_to_python(py, value)?)?;
            }
            Ok(dict.unbind().into())
        }
    }
}

fn sort_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut original = std::mem::take(map);
            let mut keys: Vec<_> = original.keys().cloned().collect();
            keys.sort();
            for key in keys {
                if let Some(mut entry) = original.remove(&key) {
                    sort_json_value(&mut entry);
                    map.insert(key, entry);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                sort_json_value(item);
            }
        }
        _ => {}
    }
}

fn adjust_yaml_indent(yaml: &str, indent: usize) -> String {
    if indent == 0 {
        return yaml.to_string();
    }
    let lines: Vec<&str> = yaml.lines().collect();
    let trailing_newline = yaml.ends_with('\n');
    let mut adjusted = String::with_capacity(yaml.len());
    for (idx, line) in lines.iter().enumerate() {
        let space_count = line.len() - line.trim_start().len();
        let level = if space_count == 0 { 0 } else { space_count / 2 };
        let trimmed = &line[space_count..];
        adjusted.push_str(&" ".repeat(level * indent));
        adjusted.push_str(trimmed);
        if idx + 1 < lines.len() || trailing_newline {
            adjusted.push('\n');
        }
    }
    adjusted
}

/// Module definition
#[pymodule]
fn yaml_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(dumps, m)?)?;
    m.add_function(wrap_pyfunction!(dumps_formatted, m)?)?;
    m.add_function(wrap_pyfunction!(loads, m)?)?;
    Ok(())
}
