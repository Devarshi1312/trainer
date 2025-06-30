import frappe

def get_context(context):
    """Fetch trainers based on search query"""

    # Get search query from form submission
    search_query = frappe.form_dict.get("search", "").strip()

    # Define filters for trainer search
    filters = {}
    if search_query:
        filters["first_name"] = ["like", f"%{search_query}%"]

    # Fetch trainers matching the query
    trainers = frappe.get_all("Trainer", fields=["name", "full_name", "image", "location"], filters=filters)

    # Add trainers and search query to context
    context.trainers = trainers
    context.search_query = search_query

    return context
