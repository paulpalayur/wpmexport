# wpmexport
This script can be used for exporting personal WPM objects like Secured Items and Web Apps.

```
PS C:\Paul\Projects\WPMExport> .\Export-WPM.ps1
Enter Identity Tenant Id: abc1234
Enter Identity User Name: user@mycompany.com
Enter subdomain: ISP_SUBDOMAIN
```
# Features
-	Works with Shared Services tenants
-	Works for Federated users as well
-	Export Secured Items and Web Apps that are owned by user
-	Export Web Apps that are shared by the Admins without credentials


# Output
The successful execution of the script will generate a `export.csv` file in the script directory
