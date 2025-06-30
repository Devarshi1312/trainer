import frappe

def redirect_after_login(login_manager):
    """Redirect users to /trainer-page after login."""
    user = login_manager.user

    # Define the one allowed user (Change this to your admin email)
    allowed_user = "admin@example.com"

    # If not the allowed user, redirect to trainer page
    if user != allowed_user:
        frappe.local.response["home_page"] = "/trainerpage"

def restrict_users(bootinfo):
    """Restrict access for all users except one."""
    user = frappe.session.user
    allowed_user = "admin@example.com"  # Change this to the actual allowed user

    if user != allowed_user:
        # Prevent access to /app (Admin Panel) and restrict backend usage
        frappe.local.response["home_page"] = "/trainer-page"

# def restrict_access():
#     allowed_pages = ["/trainerpage", "trainer-profile","/trainer-booking","/plans","/payment_success","/contact-us","/","/login"]
#     if frappe.session.user != "Administrator" and frappe.request.path not in allowed_pages:
#         frappe.local.flags.redirect_location = "/"
#         raise frappe.Redirect

