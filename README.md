# pysnyk

A Python client for the [Snyk API](https://snyk.docs.apiary.io/#).

```python
import snyk
client = snyk.SnykClient("<your-api-token>")
client.organizations()
# Return a list of Snyk organisations
client.organizations()[0].projects()
# Grab the first organisation and return a list of projects
```
