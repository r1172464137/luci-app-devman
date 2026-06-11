'use strict';
'require fs';
'require ui';

return L.view.extend({
	load: function() {
		return L.resolveDefault(fs.read('/dev/null'), null);
	},

	render: function() {
		return E('div', { class: 'cbi-map' }, [
			E('h2', {}, _('Device Rules')),
			E('p', {}, _('Rules apply only to WAN (internet) traffic. LAN traffic between devices is never affected.')),
			E('p', {}, _('Blocked devices and speed limits are configured from the Overview page.'))
		]);
	},

	handleSaveApply: null,
	handleSave: null
});
