# Femida-xss (WIP)

An automated blind-xss search plugin for Burp Suite.

### Installation
Git clone https://github.com/wish-i-was/femida.git
Burp -> Extender -> Add -> find and select blind-xss.py

## How to use

### Settings

First of all you need to setup your callback URL in field called "Your url" and press Enter to automatically save it inside config.py file.

![save_callback](https://user-images.githubusercontent.com/9287220/51000574-9e546f00-153e-11e9-8af1-e4662194a1ec.gif)

After you set it up you need to fill Payloads table with your OOB-XSS vectors, so extension will be able to inject your payloads into outgoing requests. Pay attantion that you need to set {URL} alias inside your payload, so the extension will be able to get data from "Your url" field and set it directly to your payload.

<img width="949" alt="config_example" src="https://user-images.githubusercontent.com/9287220/51000523-706f2a80-153e-11e9-8f8a-138cc257a482.png">

#### Behaviours
Femida is Random Driven Extension, so every payload with "1" inside row "Active" will be randomly used during your active or passive scanning. So if you want exclude any payload or parameter/header from testing just change the "Active" value to 0.


#### Payloads
- Add your payloads to the table using `Upload` or `Add` button.
- **DO NOT FORGET** about `{URL}` parameter in your payloads.
- When you add any data into tables, `Active` row will be manualy equal `1`. (mean it's active now)
- If you want to make it **inactive** - set `Active` row to `0`

#### Headers & Parameters
- You can add data manualy using `Add` button or in `Target`/`Proxy`/`Repeater` with right-click.

![dec-26-2018 08-08-29](https://user-images.githubusercontent.com/9287220/51000531-782ecf00-153e-11e9-8b15-dec6b8ca87d9.gif)
- Do not forget, taht headers and parameters are `case insensitive`.
- If you want to make it **inactive** - set `Active` row to `0`.

### Usage
Extension is able to perform both active and passive checks.

After all is setup you can start using extension. First case is passive checks, so we will cover this process now:
1. Press button "Run proxy", while it's active extension is looking for configured parameters and headers. After successful find it's put payload into it. If you are find some troubles during your testing (WAF or Errors or etc.) you can turn on button "Parallel Request" so all requests with a payload will be sent in a background as a duplicate requests with payloads, but your main session will be clear so you will be able to check that everything is correct just by monitoring debug log.

###### Release version soon.
###### Video soon.

Tweet us:
### [HD_421](https://twitter.com/hd_421) & [wish i was](https://twitter.com/wish_iwas)
