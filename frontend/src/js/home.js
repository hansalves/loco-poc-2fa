import van from "/js/van/van.js";
import LoadingIndicator from "./components/loading-indicator.js";
import Menu from "./components/menu.js";

const {div, h1, a, button} = van.tags;

function Home() {
	const token = sessionStorage.getItem("token");
	const user = van.state(null);
	const loading = van.state(false);

	if (token) {
		loading.val = true;
		fetch("/api/auth/current", {
			headers: {
				Authorization: `Bearer ${token}`,
			},
		})
			.then((res) => res.json())
			.then((data) => {
				user.val = data;
				loading.val = false;
			})
			.catch((e) => {
				console.error(e);
				loading.val = false;
				user.val = null;
			});
	}

	return div({class: "p-5"}, h1("2FA POC"), () => {
		if (loading.val) {
			return LoadingIndicator();
		}
		if (user.val === null) {
			return a({href: "/login"}, "login");
		}
		return div(
			`Hello ${user.val.name}`,
			Menu(() => {user.val = null}),
		);
	});
}

document.addEventListener("DOMContentLoaded", () => {
	van.add(document.body, Home());
});
