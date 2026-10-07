# Background
Provisioner tasks are tasks that are assigned to the Gateway.


# Invariants
Each provisioner task will have a task id. 
Each provisioner task will have the following state:
- Queued
- Running {task specific payload}
- Succeeded {task specific payload}
- Failed {task specific payload}
The state transitions are as follows:
- Queued -> Running {task specific payload}
- Running {task specific payload} -> Succeeded {task specific payload}
- Running {task specific payload} -> Failed {task specific payload}
- Running {task specific payload} -> Running {task specific payload} (update task specific payload)
- Queued -> Failed {task specific payload} 

Tasks will have a deadline which is relative to the time it is received by the Gateway.

# Footnote
Provisioner tasks and jobs are not the same thing. Task has its own state, the job queue is merely for scheduling and retrying.

