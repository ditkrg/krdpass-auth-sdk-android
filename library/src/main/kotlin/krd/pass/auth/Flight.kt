package krd.pass.auth

import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.Job
import java.util.concurrent.atomic.AtomicReference

/**
 * The single in-flight flow, claimed before any work starts, so a concurrent flow is told
 * [AuthResult.Busy] and a cancel arriving mid-PAR has something to settle. [settle] is the
 * one-shot terminal decision: racing finishers still deliver exactly once, and a re-entrant
 * authenticate()/signIn() from inside the callback is safe.
 */
internal class Flight {
    private val outcome = AtomicReference<AuthResult?>(null)
    private val waiter = AtomicReference<((AuthResult) -> Unit)?>(null)

    /** The state we launched with; blank until then, which fails a stray result closed. */
    @Volatile
    var expectedState: String = ""

    /** The host that launched. Null until it did; a recreated host re-adopts the flight. */
    @Volatile
    var launchOwner: LifecycleOwner? = null

    @Volatile
    var timeoutJob: Job? = null

    // A caller-specified budget, not a per-launch grant: re-adoption schedules the REMAINING
    // time, so repeatedly rotating the device can't keep extending it. Null before the launch.
    @Volatile
    var deadline: kotlin.time.ComparableTimeMark? = null

    val result: AuthResult?
        get() = outcome.get()

    /** Claim the terminal outcome. Only the winner delivers it. */
    fun settle(result: AuthResult): Boolean = outcome.compareAndSet(null, result)

    fun takeWaiter(): ((AuthResult) -> Unit)? = waiter.getAndSet(null)

    /**
     * Install [block] as the waiter. Returns the outcome when the flight settled first and found
     * no waiter to hand it to, in which case the caller delivers it itself.
     */
    fun awaitOn(block: (AuthResult) -> Unit): AuthResult? {
        waiter.set(block)
        return outcome.get()?.takeIf { takeWaiter() != null }
    }
}
