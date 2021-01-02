<?php

use MediaWiki\MediaWikiServices;
use MediaWiki\Session\SessionProvider;
use MediaWiki\Session\SessionBackend;
use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\UserInfo;

class BPAuthorizationSessionProvider extends SessionProvider {
    const SEPARATOR = ":";

    // Overridden methods

    public function canChangeUser () {
        return false;
    }

    protected function describeMessage () {
        return wfMessage('bpauthorization-provider');
    }

    public function getRememberUserDuration () {
        return null;
    }

    public function getVaryHeaders () {
        return array('Authorization' => null);
    }

    public function newSessionInfo ($id = null) {
        return null;
    }

    public function persistSession (SessionBackend $session, WebRequest $request) {
        // no-op
    }

    public function persistsSessionId () {
        return false;
    }

    public function preventSessionsForUser ($username) {
		BotPassword::removeAllPasswordsForUser($username);
	}

    /* Requests with Authorization header requires CORS preflight. */
    public function safeAgainstCsrf () {
        return true;
    }

    public function unpersistSession (WebRequest $request) {

    }

    // Private methods

    /*
        This function is taken from
        https://github.com/wikimedia/mediawiki-extensions-OAuth/blob/master/src/SessionProvider.php#L54
        Licensed under GPL v2 or later
        Credit to contributors of the OAuth extension:
        https://github.com/wikimedia/mediawiki-extensions-OAuth/graphs/contributors
    */
    private function makeException($key, ...$params) {
		global $wgHooks;

        $this->logger->info('Exception deferred: "{exc}"', [
            'exc' => $key
        ]);

		// First, schedule the throwing of the exception for later when the API
		// is ready to catch it
		$msg = wfMessage($key, $params);
		$exception = \ApiUsageException::newWithMessage(null, $msg);
		$wgHooks['ApiBeforeMain'][] = function () use ($exception) {
			throw $exception;
		};

		// Then return an appropriate SessionInfo
		$id = $this->hashToSessionId('bogus');
		return new SessionInfo(SessionInfo::MAX_PRIORITY, [
			'provider' => $this,
			'id' => $id,
			'userInfo' => UserInfo::newAnonymous(),
			'persisted' => false,
		]);
	}

    private function parseAuthorizationHeader (string $header) {
        if (strpos($header, 'Bot ') !== 0) {
            return null;
        }

        $authInfo = substr($header, 4);
        if (substr_count($authInfo, self::SEPARATOR) !== 2) {
            return null;
        }

        $authArray = explode(self::SEPARATOR, $authInfo);
        list($username, $appId, $password) = array_map(function ($item) {
            return base64_decode($item);
        }, $authArray);
        return array(
            'username' => $username,
            'appId' => $appId,
            'password' => $password
        );
    }

    // Authentication and Authorization
    public function provideSessionInfo (WebRequest $request) {
        // BotPassword is restricted to API requests
		if (!defined('MW_API') && !defined('MW_REST_API')) {
			return null;
		}

		if (!$this->config->get('EnableBotPasswords')) {
			return null;
		}

        $header = $request->getHeader('Authorization');
        if (!$header) {
            return null;
        }
        $authInfo = $this->parseAuthorizationHeader($header);
        if ($authInfo === null) {
            return null;
        }

        $username = $authInfo['username'];
        $appId = $authInfo['appId'];
        $password = $authInfo['password'];

        $user = User::newFromName($username);
        if (!$user || $user->isAnon()) {
            $this->logger->info('Tried to authenticate using unknown username "{username}"', [
                'username' => $username
            ]);
            return $this->makeException('bpauthorization-username-unknown');
        }

        $bp = BotPassword::newFromUser($user, $appId);
        if (!$bp) {
            $this->logger->info('Tried to authenticate using unknown appid "{username}@{appId}"', [
                'username' => $username,
                'appId' => $appId
            ]);
            return $this->makeException('bpauthorization-appid-unknown');
        }

        // For some reason MediaWiki decided to make getPassword private...
        $reflectionMethod = new ReflectionMethod('BotPassword', 'getPassword');
        $reflectionMethod->setAccessible(true);

        // Check the password
		$storedPassword = $reflectionMethod->invoke($bp);
		if ($storedPassword instanceof InvalidPassword) {
            $this->logger->info('Tried to authenticate using invalid bot password for "{username}@{appId}"', [
                'username' => $username,
                'appId' => $appId
            ]);
			return $this->makeException('botpasswords-needs-reset');
		}
        if (!$storedPassword->verify($password)) {
            $this->logger->info('Tried to authenticate using wrong bot password "{password}" for "{username}@{appId}"', [
                'username' => $username,
                'appId' => $appId,
                'password' => $password
            ]);
            return $this->makeException('bpauthorization-token-nomatch');
        }

        $restrictions = $bp->getRestrictions()->check($request);
        if (!$restrictions->isOK()) {
            $this->logger->info('Authentication attempt for "{username}@{appId}" failed due to restrictions', [
                'username' => $username,
                'appId' => $appId
            ]);
            return $this->makeException('bpauthorization-restricted');
        }

        $this->logger->info('Authenticated as "{username}@{appId}"', [
            'username' => $username,
            'appId' => $appId
        ]);

        return new SessionInfo(SessionInfo::MAX_PRIORITY, [
            'provider' => $this,
            'id' => $this->hashToSessionId($header),
            'userInfo' => UserInfo::newFromUser($user, true),
            'persisted' => false,
            'forceUse' => true,
            'metadata' => array(
                'rights' => \MWGrants::getGrantRights($bp->getGrants())
            )
        ]);
    }

    public function getAllowedUserRights(SessionBackend $backend) {
        if ($backend->getProvider() !== $this) {
			throw new \InvalidArgumentException('Backend\'s provider isn\'t $this');
		}
        $data = $backend->getProviderMetadata();
        if ($data && isset($data['rights']) && is_array($data['rights'])) {
            $this->logger->debug('BotPassword grants these rights for current session: {rights}', [
                'rights' => implode(',', $data['rights'])
            ]);
			return $data['rights'];
		}

        return array();
    }
}
