// Mock uclient module
export function connect(url) {
	return {
		request: function(method) {
			if (global.mock_responses && global.mock_responses[url]) {
				return global.mock_responses[url];
			}
			return { status: 404, body: "" };
		}
	};
};

export function urlencode(s) {
	return s;
};
