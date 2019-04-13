# csp-config
Build Content Security Policy from a config file. Supports different policy per page or module, and snippets you can add dynamically, if needed.

[![Build Status](https://travis-ci.org/spaze/csp-config.svg?branch=master)](https://travis-ci.org/spaze/csp-config)

The library is designed to be usable with any framework (or without one) but comes with a bridge for [Nette Framework](https://nette.org/).

> Please note that this library will only build the header value and you still need to send the header yourself!

## Installation

The best way to install the library is using [Composer](https://getcomposer.org/):

```sh
composer require spaze/csp-config
```

## Nette Framework configuration
If you're using Nette Framework you can add the extension to your config file:

```yaml
extensions:
    contentSecurityPolicy: Spaze\ContentSecurityPolicy\Bridges\Nette\ConfigExtension
```

### Example configuration

This is an example configuration, it's here to explain things and it's intentionally incomplete. You can also check [the configuration used for my site](https://github.com/spaze/michalspacek.cz/blob/master/site/app/config/contentsecuritypolicy.neon).

```yaml
contentSecurityPolicy:
    supportLegacyBrowsers: true
    snippets:
        slideshare:
            child-src:
                - https://www.slideshare.net
    policies:
        *.*:
            default-src: "'none'"
            form-action: "'none'"
            report-uri: https://report-uri.com.example.net
            report-to: default
        www.*.*:
            default-src: "'none'"
            script-src:
                - "'strict-dynamic'"
                - "'nonce'"
                - "'self'"
                - "'report-sample'"
            upgrade-insecure-requests:
        www.trainings.training:
            @extends: www.*.*
            connect-src: https://api.example.com
        admin.*.*:
            @extends: www.*.*
        admin.blog.add:
            @extends: admin.*.*
            connect-src: "'self'"
        admin.blog.edit:
            @extends: admin.blog.add
```

Let's explain:
- `supportLegacyBrowsers`
For now it takes values from `child-src` and copies them to `frame-src` because some older browsers do not understand `child-src`. By default this is disabled but you may want to enable it.

- `snippets`
This is where you define your snippets. A snippet consists of one or more Content Security Policy directives that can be added to the current Content Security Policy header with the `addSnippet(string $snippetName)` method like this: `$this->contentSecurityPolicy->addSnippet($type);` You can use it to add use it to extend your policy when there's a video on the page for example. There are sample snippets in [snippets.neon](https://github.com/spaze/csp-config/blob/master/snippets.neon) which you can directly include in your configuration if you want.

- `policies`
Your CSP policies go here. The keys below mean `[module.]presenter.action`, wildcards are supported.
  - `*.*` means *use these for all presenters and actions*. As you can see in the example above, I've used quite restrictive policy and will allow more later on. 
  - `www.*.*` applies to all presenters and actions in the "www" module.
  - `@extends: www.*.*` this configuration extends the `www.*.*` configuration, any values specified will be added. Use it to extend the default policy for some pages or actions.

Policies can contain a few special keys and values:
- keys with no values, like `upgrade-insecure-requests:` in the example above, will make the policy header contain just the key name and no values
- `'nonce'` will add a CSP nonce (`'nonce-somethingrandomandunique`') to the header. Nonces were defined in CSP2 and are used in a recommended policy using [CSP3 `'strict-dynamic'`](https://exploited.cz/xss/csp/strict.php). For this to work you'd need [spaze/nonce-generator](https://github.com/spaze/nonce-generator) which will also return the nonce so you can add it to your `<script>` tags. This can be nicely automated with [spaze/sri-macros](https://github.com/spaze/sri-macros).

### How to send the generated header in Nette Framework
```php
$header = $this->contentSecurityPolicy->getHeader($this->presenterName, $this->actionName);
if ($header) {
    $this->httpResponse->setHeader('Content-Security-Policy', $header);
}
```
