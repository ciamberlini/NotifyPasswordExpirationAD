cls
#----------------------------------------------------------------------
# Description: The current script send Alert for users before they password
# expires. You can set some values to configure this script.
#-----------------------------------------------------------------------

import-module ActiveDirectory

# Set the max day before expiration alert
$max_alert = 5

# Set STMP values
$smtpServer = "mail.organization.it"
$smtpFrom = "postmaster@organization.it"

# Administrator email (comma deliminate multiple addresses)
$adminEmail = "postmaster@organization.it"

# Organization Name
$orgName = "Organization Name"

# Public URL for password changing through web portal 
$changeurl = "https://me.organization.it"

# Function to send email to each user
function send_email_user ($remainingDays, $email, $name, $username, $account, $smtpServer, $smtpFrom)
{
	$today = Get-Date
	$dateExpires = [DateTime]::Now.AddDays($remainingDays) ;
	$smtpClient = new-object system.net.mail.smtpClient
	$mailMessage = New-Object system.net.mail.mailmessage
	$smtpClient.Host = $smtpServer
	$mailMessage.from = "supportotecnico@organization.it"
	$mailmessage.To.add($email)
	$mailMessage.Subject = "$name, la tua password di Windows sta per scadere"
	$mailMessage.IsBodyHtml = $true
	
$body = @"
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
    <style type="text/css">
BODY{font-family: Verdana, Calibri, Arial;font-size: 12px;}
    </style>
    <title></title>
  </head>
  <body>
    <p>Questo è un promemoria per avvisarti che la password dell'account <b>$account</b> scadrà tra <b>$remainingDays giorni</b>. Se non cambierai la password entro il <b>$dateExpires</b>, non potrai accedere alle risorse ed ai servizi del $orgName.</p>
	<b>Regole</b>
    <p>La nuova passwords DEVE possedere i seguenti requisiti minimi:</p>
    <ul>
      <li>Non deve contenere parti del vostro nome utente o nome e cognome</li>
      <li>Deve essere lunga almeno 10 caratteri</li>
      <li>Non può essere uguale a nessuna delle precedenti 5 password utilizzate</li>
    </ul>
    <p>Deve contenere almeno tre di queste categorie:</p>
    <ul>
      <li>Caratteri maiuscoli (Dalla A alla Z)</li>
      <li>Caratteri minuscoli (Dalla a alla z)</li>
      <li>Numeri (Da 0 a 9)</li>
      <li>Caratteri speciali (per esempio, !, $, &, %)</li>
    </ul>
	<b>Istruzioni</b>
    <p>Per cambiare password <a href="$changeurl/index.php?username=$username">cliccate qui</a> e inserite l'attuale password e la nuova password (2 volte)</p>
    <hr noshade>
    <p>Generata il : $today</p>
  </body>
</html>
"@

	$mailMessage.Body = $body
	$smtpClient.Send($mailmessage)
	#$body | out-File "usermsg.html"
}

# Send report for Admins
function send_email_admin($body, $smtpServer, $smtpFrom, $adminEmail)
{

	$smtpClient = new-object system.net.mail.smtpClient
	$mailMessage = New-Object system.net.mail.mailmessage
	$smtpClient.Host = $smtpServer
	$mailMessage.from = $smtpFrom
	
	$mailMessage.Subject = "[Report] Domain Password Expiration"
	$mailMessage.IsBodyHtml = $true
	$mailMessage.Body = $body
	$mailMessage.Body += "`n" 

	foreach ($a in $adminEmail.Split(",")){
		$mailMessage.To.add($a)
	}
	
	$smtpClient.Send($mailMessage)
}

# Search for the active directory users with following conditions
# 1. Is in USER category
# 2. Is logged in more that 1 times for eliminate the system accounts
# 3. Eliminate the Disbaled Accounts

$userlist = @()
$strFilter = "(&(objectCategory=User)(logonCount>=1)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!userAccountControl:1.2.840.113556.1.4.803:=65536))"
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.PageSize = 1000
$objSearcher.Filter = $strFilter
$colResults = $objSearcher.FindAll();

# Get the default domain password policy (Powershell 2.0)
$passPolicy = Get-ADDefaultDomainPasswordPolicy
$MaxPwdAge = [INT]$passPolicy.MaxPasswordAge.TotalDays

foreach ($objResult in $colResults)
{
	$objItem = $objResult.Properties;
	if ($objItem.mail.gettype.IsInstance -eq $True -and $objItem)
	{		
		#Transform the DateTime readable
		$userLogon = [datetime]::FromFileTime($objItem.lastlogon[0])
		$result =  $objItem.pwdlastset
		$userPwdLastSet = [datetime]::FromFileTime($result[0])

		#calculate the difference in Day
		$diffDate = [INT]([DateTime]::Now - $userPwdLastSet).TotalDays;
		
		# Get users that are about to expire but no those that are already expired
		# This way the script can run once every day without spamming users who might be on leave.
		if ((($MaxPwdAge - $diffDate) -le $max_alert) -and ($diffDate -gt 0)) {
			$selectedUser = New-Object psobject
			$selectedUser | Add-Member NoteProperty -Name "Name" -Value  $objItem.name[0]
			$selectedUser | Add-Member NoteProperty -Name "Username" -Value $objItem.samaccountname[0]
			$selectedUser | Add-Member NoteProperty -Name "Account" -Value  $objItem.userprincipalname[0]
			$selectedUser | Add-Member NoteProperty -Name "Email" -Value   $objItem.mail[0]
			
			$emailLink = "<a href='mailto:" + $objItem.mail[0] + "'>" +$objItem.mail[0] + "</a>"
			$selectedUser | Add-Member NoteProperty -Name "EmailLink" -Value $emailLink
			$selectedUser | Add-Member NoteProperty -Name "LastLogon" -Value $userLogon
			$selectedUser | Add-Member NoteProperty -Name "LastPwdSet" -Value $userPwdLastSet
			$selectedUser | Add-Member NoteProperty -Name "Ellapsed" -Value $diffDate
			$selectedUser | Add-Member NoteProperty -Name "Remaining" -Value ($MaxPwdAge-$diffDate)
			$userlist += $selectedUser
		}
	}
}

# Send email for each user
foreach ($user in $userlist )
{
	send_email_user $user.Remaining $user.Email $user.Name $user.Username $user.Account $smtpServer $smtpFrom
}

# Send email for Admins in reporting format if there are any users to report
if ( $userlist.Count -gt 0 )
{

$today = Get-Date
$style = @"
<style type="text/css">
body{background-color:#FFFFFF;font: 10pt/1.5 Verdana, Calibri, Arial;}
h1, h2, h3, h4, h5, h6 {
	line-height: 120%; 
	margin: 0 0 0.5em 0;
	color: #252525;
}
table {
	border: 1px solid #CCC;
	font-size:12px;
	white-space: nowrap;
}
th {
	border: 1px solid #CCC;
	padding: 10px;
	background-color:#FF4040;
	height: 40px;
}
td{
	border: 1px solid #CCC;
	padding: 10px;
	background-color:#FEFEFE;
	height: 40px }
</style>
"@

$body = @"
<h2>AD password expiration status report</h2>
<hr noshade/>
<p>The following users have passwords nearing expiration.</p>
<p>Generated: $today</p>
"@	

# Convert the userlist into an HTML report and email to administrators
$bodyme = $userlist | Select-Object Name, EmailLink, LastLogon, LastPwdSet, Ellapsed, Remaining |  Sort-Object "RemainingDay" |  ConvertTo-Html -Title "Active Directory password Status" -Body $body -head $style  | % {$_.replace("&lt;","<").replace("&gt;",">").replace("EmailLink","Email")} | foreach {$_ -replace "<table>", "</table><table cellspacing=0 width=90%>"}
send_email_admin $bodyme $smtpServer $smtpFrom $adminEmail
#$bodyme | out-File "output.html"

} 