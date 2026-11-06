<?php

declare(strict_types=1);

namespace Zana\Audit;

use Zana\Security\Event\PasswordResetRequested;
use Zana\Security\Event\PasswordResetTokenUsed;
use Zana\Security\Event\RecoveryCodeUsed;
use Zana\Security\Event\RoleAssigned;
use Zana\Security\Event\RoleRevoked;
use Zana\Security\Event\SecurityEvent;
use Zana\Security\Event\SignedOut;
use Zana\Security\Event\SignInFailed;
use Zana\Security\Event\SignInSucceeded;
use Zana\Security\Event\TwoFactorDisabled;
use Zana\Security\Event\TwoFactorEnabled;
use Zana\Security\Event\TwoFactorFailed;

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
            // 2.16: second factors
            $event instanceof TwoFactorEnabled, $event instanceof TwoFactorDisabled => [$event->userId, "user:{$event->userId}", null, []],
            $event instanceof TwoFactorFailed => [null, "user:{$event->userId}", $event->clientIp, ['reason' => $event->reason]],
            $event instanceof RecoveryCodeUsed => [$event->userId, "user:{$event->userId}", $event->clientIp, ['remaining' => $event->remaining]],
            // 2.17: role assignments, by whoever was signed in
            $event instanceof RoleAssigned, $event instanceof RoleRevoked => [$event->byUserId, "user:{$event->userId}", null, ['role' => $event->role, 'scope' => $event->scope]],
            default => [null, null, null, []],
        };

        $this->store->append($event->action(), $actor, $subject, $clientIp, $this->correlationId === null ? null : ($this->correlationId)(), $details);
    }
}
