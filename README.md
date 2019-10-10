# Femida-xss (WIP)

An automated blind-xss search plugin for Burp Suite.

### Installation
Git clone https://github.com/wish-i-was/femida.git
Burp -> Extender -> Add -> find and select blind-xss.py

## How to use

### Settings

First of all, you need to setup your callback URL in field called "Your url" and press Enter to automatically save it inside config.py file.

![save_callback](https://user-images.githubusercontent.com/9287220/51000574-9e546f00-153e-11e9-8af1-e4662194a1ec.gif)

After you set it up you need to fill Payloads table with your OOB-XSS vectors, so the extension will be able to inject your payloads into outgoing requests. Make sure that you properly set the {URL} alias inside your payload in order for the extension to be able to get data from the "Your url" field and adjust the payload accordingly.

<img width="949" alt="config_example" src="https://user-images.githubusercontent.com/9287220/51000523-706f2a80-153e-11e9-8f8a-138cc257a482.png">

#### Behaviours
Femida is Random Driven Extension, so every payload with "1" inside row "Active" will be randomly used during your active or passive scanning. Payloads and parameters/headers may be excluded from testing by changing their respective "Active" value to 0.

#### Payloads
- Add your payloads to the table using `Upload` or `Add` button.
- **DO NOT FORGET** about the `{URL}` parameter in your payloads.
- All parameters are enabled by default. You may exclude specific values by setting their `Active` value to 0 inside the table.

#### Headers & Parameters
- You can add data manually using the `Add` button or by right-clicking them and selecting the appropriate option in the `Target`/`Proxy`/`Repeater` tab.

![dec-26-2018 08-08-29](https://user-images.githubusercontent.com/9287220/51000531-782ecf00-153e-11e9-8b15-dec6b8ca87d9.gif)
- Do not forget that headers and parameters are `case insensitive`.
- You may exclude specific parameters by setting their `Active` value to `0`.

### Usage
The extension is able to perform both active and passive checks.

The following steps must be followed in order to perform a passive check:
1. Enable the extension and start Burp's proxy. 
1. When the extension successfully identifies a testable parameter, the payload is automatically injected into it.

If you are having problems during your testing (WAF or Errors or etc.), you may use the "Parallel Request" feature in order to send generated requests in the background without clutttering your main session, thus allowing you to debug more efficiently.

###### Release version soon.
###### Video soon.

Tweet us:
### [HD_421](https://twitter.com/hd_421) & [wish i was](https://twitter.com/wish_iwas)
