'use strict';
'require fs';
'require ui';

return L.view.extend({
	load: function() {
		return L.resolveDefault(fs.read('/dev/null'), null);
	},

	render: function() {
		var view = E('div', { class: 'cbi-map' }, [
			E('h2', {}, _('Device Manager')),
			E('div', { id: 'devman-device-list' }, [
				E('table', { class: 'table', id: 'devman-table' }, [
					E('tr', { class: 'tr table-titles' }, [
						E('th', {}, _('Alias')),
						E('th', {}, _('IP')),
						E('th', {}, _('Hostname')),
						E('th', {}, _('Speed ↓')),
						E('th', {}, _('Speed ↑')),
						E('th', {}, _('Status')),
						E('th', {}, _('Actions'))
					])
				])
			])
		]);

		this.refreshTimer = window.setInterval(L.bind(this.refresh, this), 2000);
		this.refresh();
		return view;
	},

	refresh: function() {
		L.request('admin/network/devman/api_devices', null, L.bind(function(devices) {
			var tbody = document.getElementById('devman-table');
			var rows = tbody.querySelectorAll('tr:not(.table-titles)');
			for (var i = 0; i < rows.length; i++) rows[i].remove();

			for (var i = 0; i < devices.length; i++) {
				var d = devices[i];
				var speedIn = this.formatSpeed(d.speed_in || 0);
				var speedOut = this.formatSpeed(d.speed_out || 0);
				var status = d.online ? '<span style="color:green">● ' + _('Online') + '</span>' : '<span style="color:gray">○ ' + _('Offline') + '</span>';
				var blocked = d.is_blocked ? '<span style="color:red">' + _('Blocked') + '</span>' : '';

				var actions = '';
				if (d.is_blocked) {
					actions += '<button class="btn cbi-button" onclick="devmanUnblock(' + d.id + ')">' + _('Unblock') + '</button> ';
				} else {
					actions += '<button class="btn cbi-button cbi-button-negative" onclick="devmanBlock(' + d.id + ')">' + _('Block') + '</button> ';
				}
				actions += '<button class="btn cbi-button" onclick="devmanLimit(' + d.id + ')">' + _('Limit') + '</button>';

				var tr = E('tr', {}, [
					E('td', {}, d.alias || d.hostname || 'Device-' + d.id),
					E('td', {}, d.current_ip || '-'),
					E('td', {}, d.hostname || '-'),
					E('td', {}, speedIn),
					E('td', {}, speedOut),
					E('td', {}, status + ' ' + blocked),
					E('td', {}, actions)
				]);
				tbody.appendChild(tr);
			}
		}, this));
	},

	formatSpeed: function(bps) {
		if (bps < 1000) return bps + ' bps';
		if (bps < 1000000) return (bps / 1000).toFixed(1) + ' Kbps';
		return (bps / 1000000).toFixed(1) + ' Mbps';
	},

	handleSaveApply: null,
	handleSave: null
});

// Global button handlers
window.devmanBlock = function(id) {
	L.request('admin/network/devman/api_block', { device_id: id, block: 1 });
};
window.devmanUnblock = function(id) {
	L.request('admin/network/devman/api_block', { device_id: id, block: 0 });
};
window.devmanLimit = function(id) {
	var kbps = prompt(_('Enter rate limit in kbps (0=unlimited):'), '0');
	if (kbps !== null) {
		L.request('admin/network/devman/api_limit', { device_id: id, rate_limit: parseInt(kbps) });
	}
};
