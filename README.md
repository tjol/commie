commie
======

*— comment processor for static sites —*

Commie is a small web application that processes comments (or other
user-generated content) for static blogs generated  using a tool like
[Pelican](https://blog.getpelican.com/) or [Jekyll](https://jekyllrb.com/).
It assumes the site lives in a git repository and is regenerated automatically
on a push hook.

Commie was inspired by [Staticman](https://staticman.net/). The main idea is
shared with Staticman,

 * Helps you make user-generated content appear in your statically generated
   site.
 * Keeps all the published content where it belongs: *in your git repository.*

*Also,*

 * commie doesn't rely on GitHub, but uses plain old git, hosted wherever you
   want.
 * commie doesn't send your or your users' data to any third-party services
   (no GitHub, no Akismet)
 * **commie loves email.** As an anti-spam measure, commie can require email
   verification. Commie can also email you about any new comments. Email
   verification requirements are relaxed for repeat customers with the same
   name, email, browser and IP address.
 * commie doesn't use cookies, and automatically deletes any data that's not
   checked in with the comment (e.g. email addresses) after a configurable
   amount of time. This should make it GDPR compliant.

