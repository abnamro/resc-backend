# Generic single-database configuration.

## Use Alembic to create a new migration script
<details>
  <summary>Preview</summary>
This command will create a new revision script in the ./alembic/versions directory

```bash
alembic revision -m "<revision summary>"
```
The filename is prefixed with the revision identifier used by Alembic to keep track of the revision history.
Make sure that the down_revision variable contains the identifier of the previous revision.
For instance:

```bash
#d330d086edfe_first_revision.py
revision = 'd330d086edfe'
down_revision = None
...

#e653f899efgh_second_revision.py
revision = 'e653f899efgh'
down_revision = 'd330d086edfe'
```


The generated script contains two functions:

- The upgrade function that contains the revision changes.
- The downgrade function that revert these changes.

</details>
&nbsp

## Use the --autogenerate parameter

<details>
  <summary>Preview</summary>
Alembic provide an --autogenerate parameter to help revision scripts creation. It can output the necessary changes to apply,  by comparing the current database schema
and the model stated in Python. To create that revision make sure you have a connection to a running database with an up-to-date schema version.

```bash
alembic revision --autogenerate -m "<revision summary>"
```
_**Note:**_ Autogenerate cannot detect all the required changes.The created revision script must be carefully checked and tested.
</details>
&nbsp

## Running migration and rollback
<details>
  <summary>Preview</summary>
  To upgrade/downgrade the database schema use the following:

  ```bash
  # Upgrade to specified revision identifier
  alembic upgrade <revision_identifier>

  # Upgarde to latest
  alembic upgrade head

  # Upgrade to the next revision
  alembic upgrade +1

  # Run next revision from a specific revision
  alembic upgrade <revision_identifier>+1

  # Downgrade to base (no revision applied)
  alembic downgrade base

  # Downgrade to the previous revision
  alembic downgrade -1
  ```
  _**Note:**_ A list of needed changes and a table containing alembic revision history are created during the first revision.


  You can also check current revision information:
  ```bash
  alembic current
  ```

  And the revision history:
  ```bash
  alembic history --verbose
  ```
</details>
