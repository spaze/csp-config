# csp-config
Build Content Security Policy from a config file. Supports different policy per page or module, and snippets you can add dynamically, if needed.

[![PHP Tests](https://github.com/spaze/csp-config/workflows/PHP%20Tests/badge.svg)](https://github.com/spaze/csp-config/actions?query=workflow%3A%22PHP+Tests%22)

The library is designed to be usable with any framework (or without one) but comes with a bridge for [Nette Framework](https://nette.org/).

> Please note that this library will only build the header value and you still need to send the header yourself!

## Installation

The best way to install the library is using [Composer](https://getcomposer.org/):

```sh
composer require spaze/csp-config
```

## Nette Framework configuration
If you're using Nette Framework you can add the extension to your config file:

```neon
extensions:
    contentSecurityPolicy: Spaze\ContentSecurityPolicy\Bridges\Nette\ConfigExtension
```

### Example configuration

This is an example configuration, it's here to explain things and it's intentionally incomplete. You can also check [the configuration used for my site](https://github.com/spaze/michalspacek.cz/blob/master/site/app/config/contentsecuritypolicy.neon).

```neon
contentSecurityPolicy:
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
    policiesReportOnly:
      *.*:
        default-src: "'self'"
```

Let's explain:
- `snippets`
This is where you define your snippets. A snippet consists of one or more Content Security Policy directives that can be added to the current Content Security Policy header with the `addSnippet(string $snippetName)` method like this: `$this->contentSecurityPolicy->addSnippet($type);` You can use it to add use it to extend your policy when there's a video on the page for example. There are sample snippets in [snippets.neon](https://github.com/spaze/csp-config/blob/master/snippets.neon) which you can directly include in your configuration if you want.

- `policies`
Your CSP policies go here. The keys below mean `[module.]presenter.action`, wildcards are supported.
  - `*.*` means *use these for all presenters and actions*. As you can see in the example above, I've used quite restrictive policy and will allow more later on.
  - `www.*.*` applies to all presenters and actions in the "www" module.
  - `@extends: www.*.*` this configuration extends the `www.*.*` configuration, any values specified will be added, or merged. Use it to extend the default policy for some pages or actions. You can disable merging by prefixing the directive name with `!`, effectively overwriting the extended values, [see below](#overriding-values). 

- `policiesReportOnly`
Like `policies` but intended to be used with `Content-Security-Policy-Report-Only` header, see below.

Policies can contain a few special keys and values:
- keys with no values, like `upgrade-insecure-requests:` in the example above, will make the policy header contain just the key name and no values
- `'nonce'` will add a CSP nonce (`'nonce-somethingrandomandunique`') to the header. Nonces were defined in CSP2 and are used in a recommended policy using [CSP3 `'strict-dynamic'`](https://exploited.cz/xss/csp/strict.php). For this to work [spaze/nonce-generator](https://github.com/spaze/nonce-generator) is needed. It will also return the immutable nonce so you can add it to your `<script>` tags. This can be nicely automated with [spaze/sri-macros](https://github.com/spaze/sri-macros).

#### Overriding values
If you don't want the extended values to be merged with the original values, prefix the directive name in the configuration with an exclamation mark (`!`).
Consider the following simple example configuration:

```neon
contentSecurityPolicy:
    policies:
        *.*:
            default-src: "'none'"
        www.*:
            @extends: *.*
            default-src: "'self'"
```

Calling `getHeader('www', '...')` would then return `default-src 'none' 'self'` which makes no sense and `'none'` would even be ignored.

Change the configuration to this (note the `!` prefix in `default-src`):

```neon
contentSecurityPolicy:
    policies:
        *.*:
            default-src: "'none'"
        www.*:
            @extends: *.*
            !default-src: "'self'"
```

Then calling `getHeader('www', '...')` would return `default-src 'self'` which is probably what you'd want in this case.

### How to send the generated header in Nette Framework
```php
$header = $this->contentSecurityPolicy->getHeader($this->presenterName, $this->actionName);
if ($header) {
    $this->httpResponse->setHeader('Content-Security-Policy', $header);
}
```

### Report-only policy
Use `policiesReportOnly` configuration key to define policies to use with `Content-Security-Policy-Report-Only` header:

```neon
contentSecurityPolicy:
    policies:
        *.*:
            default-src: "'none'"
    policiesReportOnly:
        *.*:
            default-src: "'self'"
```

Get the policy by calling `getHeaderReportOnly()` method:

```php
$header = $this->contentSecurityPolicy->getHeaderReportOnly($this->presenterName, $this->actionName);
if ($header) {
    $this->httpResponse->setHeader('Content-Security-Policy-Report-Only', $header);
}
```

You can send both *enforce* and *report-only* policies which is useful for policy upgrades for example:

```php
$header = $this->contentSecurityPolicy->getHeader($this->presenterName, $this->actionName);
if ($header) {
    $this->httpResponse->setHeader('Content-Security-Policy', $header);
}
$header = $this->contentSecurityPolicy->getHeaderReportOnly($this->presenterName, $this->actionName);
if ($header) {
    $this->httpResponse->setHeader('Content-Security-Policy-Report-Only', $header);
}
```
