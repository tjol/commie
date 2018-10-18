date: {{date}}
author: {{author|escape}}
{%if website %}website: {{website|escape}}
{%endif%}{%if in_reply_to%}replyto: {{in_reply_to|escape}}
{%endif%}slug: {{id}}
email_hash: {{ email_hash }}

{{text|escape}}
