BANK_SCHEMAS = {
    "SBI": {
        "table_settings": {
            "vertical_strategy": "lines",
            "horizontal_strategy": "lines",
            "intersection_x_tolerance": 5,
            "intersection_y_tolerance": 5,
        }
    },
    "HDFC": {
        "table_settings": {
            # HDFC often lacks vertical lines in digital outputs
            "vertical_strategy": "text", 
            "horizontal_strategy": "lines",
            "snap_tolerance": 3,
        }
    },
    "ICICI": {
        "table_settings": {
            "vertical_strategy": "lines",
            # ICICI sometimes spaces horizontal rows with text instead of lines
            "horizontal_strategy": "text", 
            "intersection_y_tolerance": 5,
        }
    },
    "Axis Bank": {
        "table_settings": {
            "vertical_strategy": "text",
            "horizontal_strategy": "text",
            "snap_tolerance": 4,
        }
    }
}