import van from "/js/van/van.js";
import LoadingIndicator from "/js/components/loading-indicator.js";

const {form, input, div, span, h1, label, a} = van.tags;

function MagicLink() {
	const params = new URLSearchParams(document.location.search);
	const token = params.get("token");
	const email = params.get("email");

	const totpInput = input({name: "totp", type: "text", id: crypto.randomUUID()});

	const loading = van.state(true);
	let totp_login_token = "";

	const status = van.state("login");
	const totpMsg = van.state("");
	const totpSpan = span(totpMsg);
	van.derive(() => {
		totpSpan.textContent = totpMsg.val;
	});
	const totpForm = form(
		{onsubmit: submitTOTP},
		div({class: "m-2"}, "To finish logging in, please enter the 2FA code from your authenticator app."),
		div({class: "m-2"}, label({for: totpInput.id, class: "inline-block w-48"}, "2FA Code"), totpInput),
		div({class: "m-2"}, span({class: "inline-block w-48"}), input({type: "submit", value: "Login", class: "btn"})),
		div({class: "m-2"}, totpSpan)
	);

	function handleLogin(data) {
		for (const [key, value] of Object.entries(data)) {
			sessionStorage[key] = value;
		}
		totpMsg.val = "Logged in";
		return new Promise((resolve) => {
			setTimeout(() => {
				resolve();
				window.location.href = "/";
			}, 1000);
		});
	}

	function submitTOTP(evt) {
		evt.preventDefault();
		evt.stopPropagation();
		const body = JSON.stringify({email, token: totp_login_token, totp: totpInput.value});
		loading.val = true;
		fetch("/api/auth/login-totp", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body,
		})
			.then(async (res) => {
				if (res.status === 200) {
					const data = await res.json();
					totpMsg.val = "Logged in";
					return handleLogin(data);
				} else if (res.status === 401) {
					totpMsg.val = "Invalid 2FA code";
				} else {
					totpMsg.val = "Something went wrong!";
				}
			})
			.catch((e) => {
				console.error(e);
				totpMsg.val = "Something went wrong!";
			})
			.finally(() => {
				loading.val = false;
			});
	}

	if (!token) {
		window.location.href = "/login";
	} else {
		fetch(`/api/auth/magic-link-verify`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body: JSON.stringify({token, email}),
		}).then(async (res) => {
			if (res.status === 200) {
				const data = await res.json();
				if (data.type === "Login") {
					handleLogin(data);
				} else if (data.type === "TOTPChallenge") {
					loading.val = false;
					status.val = "TOTPChallenge";
					totp_login_token = data.totp_login_token;
				} else {
					console.error(data);
					window.location.href = "/login";
				}
			} else {
				console.error(res.status, res.statusText);
				window.location.href = "/login";
			}
		});
	}
	return div(
		{class: "p-5"},
		() => (loading.val ? LoadingIndicator() : div()),
		() => (status.val === "TOTPChallenge" ? totpForm : div())
	);
}

document.addEventListener("DOMContentLoaded", () => {
	van.add(document.body, MagicLink());
});
