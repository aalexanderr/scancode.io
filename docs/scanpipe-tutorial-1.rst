.. _scanpipe_tutorial_1:

Docker Image Analysis (command line)
====================================

Requirements
------------

- **ScanCode.io is installed**, see :ref:`installation`
- **Shell access** on the machine where ScanCode.io is installed


Before you start
----------------

Download the following test Docker image and save this in your home directory:
`30-alpine-nickolashkraus-staticbox-latest.tar <https://github.com/nexB/scancode.io-tutorial/
releases/download/sample-images/30-alpine-nickolashkraus-staticbox-latest.tar>`_


Step-by-step
------------

- Open a shell in the ScanCode.io installation directory and activate the virtualenv::

    $ source bin/activate

- Create a new project named ``staticbox``::

    $ scanpipe create-project staticbox

- Add the test Docker image tarball to the project workspace's :guilabel:`input/` directory::

    $ scanpipe add-input --project staticbox \
      --input-file ~/30-alpine-nickolashkraus-staticbox-latest.tar

.. note::
    The command output will let you know where is the project workspace :guilabel:`input/` directory
    so you can browse it and check that your file was copied there correctly.
    You can also copy more files manually to this :guilabel:`input/` directory to include entire
    directories.

- Add the docker pipeline to your project::

    $ scanpipe add-pipeline --project staticbox docker

- Check that the docker pipeline was added to your project::

    $ scanpipe show-pipeline --project staticbox

.. note::
    The ``scanpipe show-pipeline`` command lists all the pipelines added to the
    project and their planned execution.
    You can use this to get a quick overview of the pipelines that have been running already
    (with their "SUCCESS" or "FAILURE" status) and those that will be running next.

- Run the docker pipeline on this project::

    $ scanpipe execute --project staticbox

- Executing the ``show-pipeline`` command again will confirm the success of the
  pipeline execution::

    $ scanpipe show-pipeline --project staticbox
    "[SUCCESS] docker"

- Get the results of the pipeline execution as a JSON file using the ``output`` command::

    $ scanpipe output --project staticbox --format json

- Open the ``output/results-<timestamp>.json`` in your preferred viewer.

----

.. note::
    The ``inputs`` and ``pipelines`` can be provided directly at once when
    calling the ``create-project`` command.
    An ``execute`` option is also available to start the pipeline execution right
    after the project creation.
    For example, the following command will create a project named ``staticbox2``,
    download the test docker image to the project's inputs, add the docker pipeline,
    and execute the pipeline in one operation::

      $ scanpipe create-project staticbox2 \
        --input-url https://github.com/nexB/scancode.io-tutorial/releases/download/sample-images/30-alpine-nickolashkraus-staticbox-latest.tar \
        --pipeline docker \
        --execute
