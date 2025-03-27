# py-apns2

simple python3 apns2 push service for iOS applications

## Scope

This primarily aims to be combined with the RegattaTech.DE Toolkit and automatically sends new race results as push notifications to iOS devices that register themselves via the companion app.

This can also trigger simple push notifications via a rudimentary API.

## Usage

- Clone the repository
- Install the requirements via `pip3 install -r requirements.txt`
- Run the server via `python3 app.py`

You need an active Apple Developer Subscription.
This can be obtained via the Apple Developer Portal.
You should also be familiar with how notifications work on iOS.

You also need an iOS application that registers itself with the server.


## Endpoints

### /api/registerDeviceToken
POST json with `device_token` to register
Needs to be authenticated with `REGISTER_AUTH` (defined in config.ini)

### /api/customnotify
POST json with `severity` and `notification` to send a custom notification
Needs to be authenticated with `MANAGE_AUTH` (defined in config.ini)

severity can be one of `info`, `warning`, `urgent`, `danger`

### /api/deleteAllDeviceTokens
Deletes all registered device tokens
Needs to be authenticated with `MANAGE_AUTH` (defined in config.ini)

### /shownotificationlog
Shows all send notifications
Needs to be authenticated with `MANAGE_AUTH` (defined in config.ini)

### /showdevicetokens
Shows all registered device tokens
Needs to be authenticated with `MANAGE_AUTH` (defined in config.ini)

### /api/getresults
Gets the results from the result API, checks for new results and sends out the notification.
Needs to be authenticated with `MANAGE_AUTH` (defined in config.ini)