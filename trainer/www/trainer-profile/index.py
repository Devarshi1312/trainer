import frappe

def get_context(context):
    """Add data to the context for rendering the trainer profile page"""
    
    # Get trainer_id from query parameters
    trainer_id = frappe.form_dict.get('trainer_id')
    
    if not trainer_id:
        frappe.local.flags.redirect_location = '/404'
        raise frappe.Redirect

    try:
        # Fetch trainer data
        trainer = frappe.get_doc('Trainer', trainer_id)

        # Check permissions explicitly
        if not trainer.has_permission("read"):
            frappe.local.flags.redirect_location = '/403'  # Forbidden
            raise frappe.Redirect
        
        # Add trainer data to context
        context.trainer = trainer
        
    except frappe.DoesNotExistError:
        frappe.local.flags.redirect_location = '/404'
        raise frappe.Redirect
    
    return context
