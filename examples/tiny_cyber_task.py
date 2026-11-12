"""A tiny Inspect task used to produce real example logs with mockllm."""

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import includes


@task
def cyber_smoke() -> Task:
    return Task(
        dataset=[
            Sample(input="Name a common web vulnerability class.", target="Default output"),
            Sample(input="Name another one.", target="Default output"),
        ],
        scorer=includes(),
        tags=["cybersecurity"],
    )
