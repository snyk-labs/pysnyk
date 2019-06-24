# pysnyk

A Python client for the [Snyk API](https://snyk.docs.apiary.io/#).

## Usage

Using the client requires you to provide your Snyk API token.

```python
import snyk
client = snyk.SnykClient("<your-api-token>")
```

### Organizations

With the client we can get a list of Snyk organizations you are a member of:

```python
client.organizations
```

This returns a list of `snyk.models.Organization` objects.

If you already have the ID of the organization you're after you can grab it directly:

```python
client.organization("<organization-id>")
```

This will return a single `snyk.models.Organization` object.

Most of the API is scoped to organizations, so most other methods are found on the `snyk.models.Organization` objects
returned by these two methods.

The `snyk.models.Organization` object has the following properties related to the API:

* `members` - returns a list of members of the organization
* `entitlements` - returns the set of Snyk features available to this account
* `licenses` - returns the list of licenses currently in use by projects in this organisation
* `projects` - the list of associated projects, see below for more details

## Projects

Once you have an organization you're likely to want to grab a particular project:

```python
client.organizations[0].projects
```

This will return a list of `snyk.models.Project` objects.

In the case where you want to get all of the projects across all of your organizations then you can use the handy
method on the client.

```python
client.projects
```

The `snyk.models.Project` object has the following useful properties and methods:

* `issues`
* `delete()`
* `settings`
* `ignores`
* `jira_issues`
* `dependency_graph`
* `dependencies()`
* `licenses`

