app_name = "trainer"
app_title = "Trainer"
app_publisher = "Devarshi"
app_description = "Training purpose"
app_email = "devarshi.b@cumulations.com"
app_license = "mit"

# Apps
# ------------------

# required_apps = []

# Each item in the list will be shown as an app in the apps page
# add_to_apps_screen = [
# 	{
# 		"name": "trainer",
# 		"logo": "/assets/trainer/logo.png",
# 		"title": "Trainer",
# 		"route": "/trainer",
# 		"has_permission": "trainer.api.permission.has_app_permission"
# 	}
# ]

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/trainer/css/trainer.css"
# app_include_js = "/assets/trainer/js/trainer.js"

# include js, css files in header of web template
# web_include_css = "/assets/trainer/css/trainer.css"
# web_include_js = "/assets/trainer/js/trainer.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "trainer/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "trainer/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "trainer.utils.jinja_methods",
# 	"filters": "trainer.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "trainer.install.before_install"
# after_install = "trainer.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "trainer.uninstall.before_uninstall"
# after_uninstall = "trainer.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "trainer.utils.before_app_install"
# after_app_install = "trainer.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "trainer.utils.before_app_uninstall"
# after_app_uninstall = "trainer.utils.after_app_uninstall"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "trainer.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# DocType Class
# ---------------
# Override standard doctype classes

# override_doctype_class = {
# 	"ToDo": "custom_app.overrides.CustomToDo"
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
# 	}
# }

# Scheduled Tasks
# ---------------

# scheduler_events = {
# 	"all": [
# 		"trainer.tasks.all"
# 	],
# 	"daily": [
# 		"trainer.tasks.daily"
# 	],
# 	"hourly": [
# 		"trainer.tasks.hourly"
# 	],
# 	"weekly": [
# 		"trainer.tasks.weekly"
# 	],
# 	"monthly": [
# 		"trainer.tasks.monthly"
# 	],
# }

# Testing
# -------

# before_tests = "trainer.install.before_tests"

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "trainer.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "trainer.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["trainer.utils.before_request"]
# after_request = ["trainer.utils.after_request"]

# Job Events
# ----------
# before_job = ["trainer.utils.before_job"]
# after_job = ["trainer.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"trainer.auth.validate"
# ]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# default_log_clearing_doctypes = {
# 	"Logging DocType Name": 30  # days to retain logs
# }

# hooks.py in your custom app
# hooks.py in your custom app

# Redirect users to trainer page after login
on_session_creation = "trainer.utils.redirect_after_login"

# Restrict all users except one
boot_session = "trainer.utils.restrict_users"

# Restrict access to certain pages
# before_request = "trainer.utils.restrict_access"

fixtures = [
    {"dt": "DocType", "filters": [["name", "in", [
        "Trainer",
        "Trainer_Workshop_List",
        "Clients_Worked",
        "Testimonials",
        "Trainer_Education",
        "Credit Transaction",
        "Ratings_Reviews",
        "Wishlist",
        "Credits",
        "Trainer_Certificates",
        "Trainer_Expertise",
        "Workshop_Image_List",
        "Credit_Pricing",
        "Trainer_Languages",
        "Unlocked Trainers"
    ]]]}
]
