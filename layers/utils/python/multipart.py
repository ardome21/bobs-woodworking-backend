import cgi
from io import BytesIO

def parse_multipart_formdata(body_bytes, content_type):
    """
    Parse multipart/form-data without external dependencies.
    Returns a dictionary of field names to values.
    """
    # Parse content type to get boundary
    ctype, pdict = cgi.parse_header(content_type)

    if ctype != 'multipart/form-data':
        raise ValueError(f"Expected multipart/form-data, got {ctype}")
    
    if 'boundary' not in pdict:
        raise ValueError("No boundary found in Content-Type header")
    
    # Ensure boundary is bytes
    pdict['boundary'] = pdict['boundary'].encode('utf-8') if isinstance(pdict['boundary'], str) else pdict['boundary']
    
    # Parse multipart form data
    fields = cgi.parse_multipart(BytesIO(body_bytes), pdict)
    
    # Separate text fields and files
    text_fields = {}
    file_fields = {}

    for field_name, field_values in fields.items():
        if not field_values:
            continue

        # Check if this field has multiple values (e.g., multiple images)
        if len(field_values) > 1:
            # Handle multiple files with the same field name
            for idx, value in enumerate(field_values):
                if isinstance(value, bytes):
                    try:
                        decoded_value = value.decode('utf-8')
                        # For text fields with multiple values, keep the last one
                        text_fields[field_name] = decoded_value
                    except UnicodeDecodeError:
                        # Store files with unique keys
                        file_fields[f"{field_name}_{idx}"] = value
                else:
                    text_fields[field_name] = value
        else:
            # Single value - original logic
            value = field_values[0]
            if isinstance(value, bytes):
                try:
                    decoded_value = value.decode('utf-8')
                    text_fields[field_name] = decoded_value
                except UnicodeDecodeError:
                    # Keep as bytes for files
                    file_fields[field_name] = value
            else:
                text_fields[field_name] = value

    return text_fields, file_fields