import frappe

def get_context(context):    
    # Fetch unlocked trainers for the current user
    search_query = frappe.form_dict.get("search", "").strip()

    unlocked_trainers = frappe.get_all(
        "Unlocked Trainers", 
        fields=["trainer"], 
        filters={"user": frappe.session.user}, 
        ignore_permissions=False
    )  

    # Fetch all trainers
    all_trainers = frappe.get_all(
        "Trainer", 
        fields=["name"], 
        ignore_permissions=False
    )

    # Ensure lists are initialized properly
    unlocked_trainers_list = [trainer["trainer"] for trainer in unlocked_trainers] if len(unlocked_trainers) > 0 else []
    all_trainers_list = [trainer["name"] for trainer in all_trainers] if len(all_trainers) > 0 else []

    unlocked_trainers_data = []

    # Define filters for trainer search
    filters = {}
    if search_query:
        filters["first_name"] = ["like", f"%{search_query}%"]

    # Fetch trainers matching the query
    trainers = frappe.get_all("Trainer", fields=["name", "full_name", "image", "location"], filters=filters)
    credits=frappe.get_all("Credits",fields=["credits"],filters={"user":frappe.session.user})
    try:
        # If trainers exist, process them
        if len(all_trainers_list) > 0:
            for trainer in all_trainers_list:
                if trainer not in unlocked_trainers_list:
                    trainers.append(trainer)
                else:
                    unlocked_trainers_data.append(trainer)

        # Ensure lists are never empty to prevent errors in Jinja filters
        context.trainers = trainers if len(trainers) > 0 else ["__invalid__"]
        context.unlocked_trainers_data = unlocked_trainers_data if len(unlocked_trainers_data) > 0 else ["__invalid__"]
        context.credits = int(credits[0]["credits"]) if credits else 0
        context.search_query = search_query
    except frappe.DoesNotExistError:
        frappe.local.flags.redirect_location = '/404'
        raise frappe.Redirect

    return context
