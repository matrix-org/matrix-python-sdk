import logging
from collections import defaultdict
from threading import Thread, Condition, Event

from matrix_client.errors import MatrixHttpLibError, MatrixRequestError

logger = logging.getLogger(__name__)


class DeviceList:
    """Allows to maintain a list of devices up-to-date for an OlmDevice.

    Offers blocking and non-blocking methods to fetch device keys when appropriate.
    NOTE: Spawns a thread that will last until program termination.

    Args:
        olm_device (OlmDevice): Will be used to get additional info, such as device id.
        api (MatrixHttpApi): The api object used to make requests.
        device_keys (defaultdict(dict)): A map from user to device to keys.
    """

    def __init__(self, olm_device, api, device_keys):
        self.olm_device = olm_device
        self.api = api
        self.device_keys = device_keys
        # Stores the ids of users who need updating
        self.outdated_user_ids = _OutdatedUsersSet()
        # Stores the ids of users we are currently tracking. We can assume the device
        # keys of these users are up-to-date as long as no downloading is in progress.
        # We should track every user we share an encrypted room with.
        self.tracked_user_ids = set()
        # Allows to wake up the thread when there are new users to update, and to
        # synchronise shared data.
        self.thread_condition = Condition()
        self.update_thread = _UpdateDeviceList(
            self.thread_condition, self.outdated_user_ids, self._download_device_keys,
            self.tracked_user_ids
        )
        self.update_thread.start()

    def get_room_device_keys(self, room, blocking=True):
        """Gets the keys of all devices present in the room.

        Makes sure not to download keys of users we are already tracking.
        The users we were not yet tracking will get tracked automatically.

        Args:
            room (Room): The room to use.
            blocking (bool): Optional. Whether to wait for the keys to have been
                downloaded before returning.
        """
        logger.info('Fetching all missing keys in room %s.', room.room_id)
        user_ids = {u.user_id for u in room.get_joined_members()} - self.tracked_user_ids
        if not user_ids:
            logger.info('Already had all the keys in room %s.', room.room_id)
            if blocking:
                # Wait on an eventual download to finish
                self.update_thread.event.wait()
            return
        with self.thread_condition:
            self.outdated_user_ids.update(user_ids)
            if blocking:
                # Will ensure the user_ids we just added are processed
                event = Event()
                self.outdated_user_ids.events.add(event)
            self.thread_condition.notify()
        if blocking:
            event.wait()

    def add_users(self, user_ids):
        """Add users to be tracked, and download their device keys.

        NOTE: this is non-blocking and will return before the keys are downloaded.

        Args:
            user_ids (iterable): Any iterable containing user ids.
        """
        user_ids = user_ids.difference(self.tracked_user_ids)
        if user_ids:
            self._add_outdated_users(user_ids)

    def stop_tracking_users(self, user_ids):
        """Stop tracking users.

        NOTE: Keys will not be deleted.

        Args:
            user_ids (iterable): Any iterable containing user ids.
        """
        with self.thread_condition:
            self.tracked_user_ids.difference_update(user_ids)
            self.outdated_user_ids.difference_update(user_ids)
        logger.info('Stopped tracking users: %s.', user_ids)

    def update_user_device_keys(self, user_ids, since_token=None):
        """Triggers an update for users we already track.

        Args:
            user_ids (iterable): Any iterable containing user ids.
            since_token (str): Optional. Since token of a sync request, if triggering
                the update as a result of that sync request.
        """
        user_ids = self.tracked_user_ids.intersection(user_ids)
        if not user_ids:
            return
        logger.info('Updating the device lists of users: %s, using token %s',
                    user_ids, since_token)
        self._add_outdated_users(user_ids, since_token=since_token)

    def _add_outdated_users(self, user_ids, since_token=None):
        """Stop tracking users. Keys will not be deleted.

        Args:
            user_ids (iterable): Any iterable containing user ids.
            since_token (str): Optional. Since token of a sync request.
        """
        with self.thread_condition:
            self.outdated_user_ids.update(user_ids)
            if since_token:
                self.outdated_user_ids.sync_token = since_token
            self.thread_condition.notify()

    def _download_device_keys(self, user_devices, since_token=None):
        """Download and store device keys, if they pass security checks.

        Args:
            user_devices (dict): Format is ``user_id: [device_ids]``.
            since_token (str): Optional. Since token of a sync request.
        """
        changed = defaultdict(dict)
        resp = self.api.query_keys(user_devices, token=since_token)
        if resp.get('failures'):
            logger.warning('Failed to download keys from the following unreachable '
                           'homeservers %s.', resp['failures'])
        device_keys = resp['device_keys']
        for user_id in user_devices:
            # The response might not contain every user_ids we requested
            for device_id, payload in device_keys.get(user_id, {}).items():
                if device_id == self.olm_device.device_id:
                    continue
                if payload['user_id'] != user_id or payload['device_id'] != device_id:
                    logger.warning('Mismatch in keys payload of device %s (%s) of user '
                                   '%s (%s).', payload['device_id'], device_id,
                                   payload['user_id'], user_id)
                    continue
                try:
                    signing_key = payload['keys']['ed25519:{}'.format(device_id)]
                    curve_key = payload['keys']['curve25519:{}'.format(device_id)]
                except KeyError as e:
                    logger.warning('Invalid identity keys payload from device %s of'
                                   'user %s: %s.', device_id, user_id, e)
                    continue
                verified = self.olm_device.verify_json(
                    payload, signing_key, user_id, device_id)
                if not verified:
                    logger.warning('Signature verification failed for device %s of '
                                   'user %s.', device_id, user_id)
                    continue
                keys = self.device_keys[user_id].setdefault(device_id, {})
                if keys:
                    if keys['ed25519'] != signing_key:
                        logger.warning('Ed25519 key has changed for device %s of '
                                       'user %s.', device_id, user_id)
                        continue
                    if keys['curve25519'] == curve_key:
                        continue
                else:
                    keys['ed25519'] = signing_key
                keys['curve25519'] = curve_key
                changed[user_id][device_id] = keys

        logger.info('Successfully downloaded keys for devices: %s.',
                    {user_id: list(changed[user_id]) for user_id in changed})
        return changed


class _OutdatedUsersSet(set):
    """Allows to know if elements in a set have been processed.

    This is done by adding elements along with an Event object. Then, functions
    processing the set should set the events when they are done.
    """

    def __init__(self, iterable=()):
        self.events = set()
        self._sync_token = None
        super(_OutdatedUsersSet, self).__init__(iterable)

    def mark_as_processed(self):
        for event in self.events:
            event.set()

    def copy(self):
        new_set = _OutdatedUsersSet(self)
        new_set.events = self.events.copy()
        return new_set

    def clear(self):
        self.events.clear()
        super(_OutdatedUsersSet, self).clear()

    def update(self, iterable):
        super(_OutdatedUsersSet, self).update(iterable)
        if isinstance(iterable, _OutdatedUsersSet):
            self.events.update(iterable.events)

    @property
    def sync_token(self):
        return self._sync_token

    @sync_token.setter
    def sync_token(self, token):
        if not self._sync_token or token > self._sync_token:
            self._sync_token = token


class _UpdateDeviceList(Thread):

    def __init__(self, cond, user_ids, download_method, tracked_user_ids):
        # We wait on this condition when there is nothing to do. Outside code should use
        # it to notify us when they add data to be processed in outdated_user_ids so that
        # we can wake up and process it.
        self.cond = cond
        self.outdated_user_ids = user_ids
        self.download = download_method
        self.tracked_user_ids = tracked_user_ids
        # Cleared when we start a download, and set when we have finished it. This can be
        # used by outside code in order to know if we are in the middle of a download, and
        # allows to wait for it to complete by waiting on this event.
        self.event = Event()
        # Used internally to terminate gracefully on program exit.
        self._should_terminate = Event()
        super(_UpdateDeviceList, self).__init__()

    def run(self):
        while True and not self._should_terminate.is_set():
            with self.cond:
                while not self.outdated_user_ids:
                    # Avoid any deadlocks
                    self.outdated_user_ids.mark_as_processed()
                    self.event.set()
                    logger.debug('Update thread is going to sleep...')
                    self.cond.wait()
                    logger.debug('Update thread woke up!')
                    if self._should_terminate.is_set():
                        return
                to_download = self.outdated_user_ids.copy()
                self.outdated_user_ids.clear()
                self.event.clear()
                self.tracked_user_ids.update(to_download)
            payload = {user_id: [] for user_id in to_download}
            logger.info('Downloading device keys for users: %s.', to_download)
            try:
                self.download(payload, self.outdated_user_ids.sync_token)
                self.event.set()
                to_download.mark_as_processed()
            except (MatrixHttpLibError, MatrixRequestError) as e:
                logger.warning('Network error when fetching device keys (will retry): %s',
                               e)
                with self.cond:
                    self.outdated_user_ids.update(to_download)

    def join(self, timeout=None):
        # If we are joined, this means that the main program is terminating.
        # We should terminate too.
        self._should_terminate.set()
        with self.cond:
            self.cond.notify()
        super(_UpdateDeviceList, self).join(timeout=timeout)
