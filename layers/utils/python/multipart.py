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
        if field_values:
            value = field_values[0]
            # Try to decode as text
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