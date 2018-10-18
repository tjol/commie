commie
======

*— comment processor for static sites —*

*[see it in action!](https://tjol.eu/blog/commie.html)*)

Commie is a small web application that processes comments (or other
user-generated content) for static blogs generated  using a tool like
[Pelican][plcn] or [Jekyll][jkrb]. It assumes the site lives in a git
repository and is regenerated automatically on a push hook.

Commie was inspired by [Staticman][sm]. The main idea is
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
 * while commie is a service you have to run on an internet-accessible server 
   (losing a benefit of a static site), it is not required to serve your site
   in and of itself. Commie does not require a database server or anything like
   that.
 * Commie works great with the [Pelican Comment System][PCS] if you add a custom
   comment form!

Commie powers the comments sections at [tjol.eu](https://tjol.eu)

[plcn]: https://blog.getpelican.com/
[jkrb]: https://jekyllrb.com/
[sm]: https://staticman.net/
[PCS]: https://github.com/getpelican/pelican-plugins/tree/master/pelican_comment_system

### Setup

Commie requires:

 * Python **3.7** (or newer)
 * [Flask](http://flask.pocoo.org/) and the other dependencies in `requirements.txt`
 * An SMTP server that will accept its mail
 * [Git](https://git-scm.com/), and a target git repository which should have a
   suitable `post-receive` hook to rebuild your site.
 * A server that can run WSGI apps with a new enough Python (like uWSGI)

Commie needs a configuration file called `commie.yaml` in this directory. The
example file `commie.yaml.example` lists all the possible options with short
explanations that should be clear enough.

You can configure multiple sites (called “roots” by commie) in one commie
instance, each with its own block in `commie.yaml`. The name of your site goes
right at the top; if you call your site the *“People's front of Judea”*, then
the first line of `commie.yaml` should be `People's front of Judea:`. 

Comments are submitted by `POST` as normal form data to
`https://path/to/commie/submit`. A comment submission form needs to supply the
hidden field `root`, the name of the site, a field `email` with the user's email
address, and any required fields listed in the config file. This should normally
include a reference to which post the comment refers to, which might be called
`slug`.

    <form method="POST" action="/commie/submit">
        <input type="hidden" name="root" value="People's front of Judea">
        <input type="hidden" name="slug" value="an-ode-to-splitters">
        <label for="email">Email address:</label> <input id="email" name="email"><br>
        <!-- ... -->
    </form>

Commie automatically starts a background process to do things like sending email,
pushing to git and cleaning up old files. To make sure this works, call
`http://path/to/commie/ping`. You can start this manually if you wish by running
something like `FLASK_APP=commie flask commie-worker`.
