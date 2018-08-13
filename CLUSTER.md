# Clustering ods-rpc

> *The ods-rpc daemon is an API over which domains can enter and leave the
> signed and chained states.  This is a global action, so any clustered
> solution might run multiple ods-rpc instances only when these
> synchronise their state.*

State in terms of ods-rpc means flags stored in `/var/opendnssec/rpc` or,
as a special form, lack of a flag.  This state needs to be synchronised
between instances of ods-rpc in a cluster.

Since the work involves consecutive operations that adhere to a state
diagram, it would be an error to let an older change overtake a newer one.
Because of this, we choose to find a timestamp for any changes, and use it
to decide whether an update should be processed.

When an action over the API sets a flag (or resets it, which is just a
variation in terms of what is being stored, namely absense of the underlying
file), the timestamp of the action is recorded.  Since this is done in response
to a live action, that timestamp is always the current time, so it is always
the newest action.

Changes to flags can be communicated to the other node(s) in a cluster,
annotated with the timestamp of the action.  Assuming a queueing solution
such as RabbitMQ, such changes can be stuck in a queue for some time before
they arrive at the other node(s).  In this case, only newer changes should be
processed.  Note how changes reflecting back at one's own node in the cluster
would be ignored, which means that infinite repeating of the same actions can
be avoided.  New actions should of course not be initiated if no change was
affected, and not before affecting it either.

**Intermezzo:**
Keep in mind that the state diagram enforces a strict order to actions, so
that it is even safe to try an action when an update was lost on another
system; for example, sending a `goto_XXX` statement to one machine just before
it goes down can be followed by the same `goto_XXX` to another machine even
when the update was missed.  In the future, when the crashed system comes back
up and sends the changes to the second machine it will be ignored because the
`goto_XXX` would have overtaken the work.  Commands other then `goto_XXX` and
`assert_XXX` are not as adaptive in terms of state diagram updates, so there
may be errors that would be reported, but it is a normal course of action to
monitor log files after a crash has occurred, so it should not be unnoticed.

One remaining question is what timestamp should be used for comparison on the
receiving system.  For most flags, this would be the last change of the
flag file.  One exception is the removal of a flag, but for that it is quite
possible to instead use the timestamp of the last change to the directory
holding the flag files.

## Starting a Cluster Node

When a cluster node starts, it can record time stamps for all the flags, and
continue to check the queues arriving from other nodes for updates.  It should
process such updates in order, so multiple streams of updates should be sorted
in time order.  Since the streams are time-ordered anyway, this need not be
done per flag but can be done per stream.
(**Note:** We currently assume two nodes, so we do not need
to order updates as our own are easily ignored.)

When another node (or its queue) comes online and starts sending (older)
updates at any later time, it is easily tested whether they apply; for flags
that are locally known, then a simple comparison with the local file's
timestamp can be made.  If there is no such local file and flag state is
being added, then TODO.  This situation can be avoided with clustered queues
such as RabbitMQ, which result in a transaction commit only when the queue
has been replicated.

