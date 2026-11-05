<?php

declare(strict_types=1);

namespace Zana\Audit;

use Zana\Security\Event\PasswordResetRequested;
use Zana\Security\Event\PasswordResetTokenUsed;
use Zana\Security\Event\SecurityEvent;
use Zana\Security\Event\SignedOut;
use Zana\Security\Event\SignInFailed;
use Zana\Security\Event\SignInSucceeded;

/**
 * Records mj-zana/security's events in the security audit log (FE-58):
 * sign-ins, failed sign-ins (with the login typed, never the password),
 * sign-outs and password resets. Registered as a listener when
 * audit.log.enabled is true. The events carry the user and the client
 * address; the correlation id comes from the log context when
 * mj-zana/logging is installed.
 */
final readonly class SecurityEventsRecorder
{
    /**
     * @param (\Closure(): ?string)|null $correlationId
     */
    public function __construct(private AuditLogStore $store, private ?\Closure $correlationId = null)
    {
    }

    public function __invoke(SecurityEvent $event): void
    {
        [$actor, $subject, $clientIp, $details] = match (true) {
            $event instanceof SignInSucceeded => [$event->userId, "user:{$event->userId}", $event->clientIp, ['method' => $event->method]],
            $event instanceof SignInFailed => [null, null, $event->clientIp, ['login' => $event->login, 'reason' => $event->reason]],
            $event instanceof SignedOut => [$event->userId, "user:{$event->userId}", $event->clientIp, []],
            $event instanceof PasswordResetRequested, $event instanceof PasswordResetTokenUsed => [null, "user:{$event->userId}", null, []],
            default => [null, null, null, []],
        };

        $this->store->append($event->action(), $actor, $subject, $clientIp, $this->correlationId === null ? null : ($this->correlationId)(), $details);
    }
}
