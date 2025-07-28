import van from "/js/van/van.js";

const {button, a, div} = van.tags;

export default function Menu(logoutCallback) {

	const userName = van.state(sessionStorage.getItem("name"));

	function logout(evt) {
		evt.preventDefault();
		sessionStorage.clear();
		if (logoutCallback) {
			logoutCallback();
		} else {
			window.location.href = "/login";
		}
	}

	return div(
		{class: "flex flex-row"},
		div({class: "basis-[1] p-2"}, a({href: "/"}, "🏠 home")),
		() => (userName.val ? div({class: "basis-[1] p-2"}, a({href: "/account"}, `👤 ${userName.val} account`)) : div()),
		() => (userName.val ? div({class: "basis-[1] p-2"}, button({class: "link", onclick: logout}, "🚪 logout")) : div())
	);
}
