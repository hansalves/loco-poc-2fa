import van from "/js/van/van.js";
import LoadingIndicator from "./components/loading-indicator.js";
import Menu from "./components/menu.js";

const {form, input, div, span, h1, h2, label, button, img} = van.tags;

function ChangePassword() {
	const message = van.state("");
	const loading = van.state(false);
	const oldPasswordInput = input({
		type: "password",
		name: "old_password",
		required: true,
		placeholder: "Old Password",
		id: crypto.randomUUID(),
	});
	const newPasswordInput = input({
		type: "password",
		name: "new_password",
		required: true,
		placeholder: "New Password",
		id: crypto.randomUUID(),
		onchange: () => {
			confirmPasswordInput.setCustomValidity("");
			confirmPasswordInput.reportValidity();
		},
	});
	const confirmPasswordInput = input({
		type: "password",
		name: "confirm_password",
		required: true,
		placeholder: "Confirm Password",
		id: crypto.randomUUID(),
		onchange: () => {
			confirmPasswordInput.setCustomValidity("");
			confirmPasswordInput.reportValidity();
		},
	});
	function submit(evt) {
		const token = sessionStorage.getItem("token");
		evt.preventDefault();
		evt.stopPropagation();
		message.val = "";
		const newPassword = newPasswordInput.value;
		const confirmPassword = confirmPasswordInput.value;
		if (newPassword !== confirmPassword) {
			confirmPasswordInput.setCustomValidity("Passwords do not match");
			confirmPasswordInput.reportValidity();
			return;
		}
		loading.val = true;
		fetch("/api/auth/change-password", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${token}`,
			},
			body: JSON.stringify({old_password: oldPasswordInput.value, new_password: newPassword}),
		})
			.then((res) => {
				if (res.status === 200) {
					message.val = "Password changed successfully";
				} else {
					message.val = "Failed to change password";
				}
			})
			.catch((e) => {
				console.error(e);
				message.val = "Failed to change password";
			})
			.finally(() => {
				loading.val = false;
			});
	}
	return div(
		{class: "my-8 border rounded-lg p-2 relative"},
		form(
			{onsubmit: submit},
			() => (loading.val ? LoadingIndicator() : div()),
			div(
				{class: "m-2"},
				label({for: oldPasswordInput.id, class: "inline-block w-48"}, "Old Password"),
				oldPasswordInput
			),
			div(
				{class: "m-2"},
				label({for: newPasswordInput.id, class: "inline-block w-48"}, "New Password"),
				newPasswordInput
			),
			div(
				{class: "m-2"},
				label({for: confirmPasswordInput.id, class: "inline-block w-48"}, "Confirm Password"),
				confirmPasswordInput
			),
			div({class: "m-2"}, span({class: "inline-block w-48"}), input({type: "submit", value: "Change Password"})),
			div({class: "mx-2 my-8"}, span(message))
		)
	);
}

function TOTPSetup(isSetup) {
	const message = van.state("");
	const loading = van.state(false);
	const status = van.state(isSetup ? "complete" : "start");
	const qrCode = van.state("");
	const url = van.state("");

	function startFlow() {
		message.val = "";
		status.val = "register";
	}

	function submitRegister(evt) {
		evt.preventDefault();
		evt.stopPropagation();
		message.val = "";
		const token = sessionStorage.getItem("token");
		const formData = new FormData(evt.target);
		const requestBody = JSON.stringify(Object.fromEntries(formData));
		loading.val = true;
		fetch("/api/auth/register-totp", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${token}`,
			},
			body: requestBody,
		})
			.then((res) => {
				if (res.status === 200) {
					return res.json();
				} else if (res.status === 401) {
					message.val = "Invalid password";
					status.val = "register";
				} else {
					return Promise.reject(new Error(`${res.status} ${res.statusText}`));
				}
			})
			.then((data) => {
				if (data) {
					qrCode.val = data.qr_code;
					url.val = data.url;
					status.val = "verify";
				}
			})
			.catch((e) => {
				console.error(e);
				message.val = "Failed to start 2FA setup";
				status.val = "start";
			})
			.finally(() => {
				loading.val = false;
			});
	}

	function submitVerify(evt) {
		evt.preventDefault();
		evt.stopPropagation();
		message.val = "";
		const token = sessionStorage.getItem("token");
		const formData = new FormData(evt.target);
		const requestBody = JSON.stringify(Object.fromEntries(formData));
		loading.val = true;
		fetch("/api/auth/verify-totp", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${token}`,
			},
			body: requestBody,
		})
			.then((res) => {
				if (res.status === 200) {
					return res.json();
				} else {
					return Promise.reject(new Error(`${res.status} ${res.statusText}`));
				}
			})
			.then((data) => {
				// for now the body doesn't contain anything
				message.val = "2FA setup completed";
				status.val = "complete";
			})
			.catch((e) => {
				console.error(e);
				message.val = "Failed to verify 2FA";
				status.val = "verify";
			})
			.finally(() => {
				loading.val = false;
			});
	}

	function flow() {
		if (status.val === "start") {
			return div(
				{class: "p-2"},
				div({class: "my-2"}, "To keep your account secure, we recommend setting up 2FA."),
				button({class: "btn", onclick: startFlow}, "Setup 2FA")
			);
		} else if (status.val === "register") {
			return form(
				{onsubmit: submitRegister},
				div({class: "my-2"}, "To make sure you are the owner of this account, please enter your password."),
				div({class: "my-2"}, input({type: "password", name: "password", placeholder: "Password", required: true})),
				div({class: "my-2"}, input({type: "submit", value: "Register"}))
			);
		} else if (status.val === "verify") {
			return form(
				{onsubmit: submitVerify},
				div("Scan the QR code with your authenticator app and enter the code below."),
				img({src: `data:image/png;base64,${qrCode.val}`}),
				div({class: "my-2"}, url),
				div({class: "my-2"}, input({type: "text", name: "totp", placeholder: "Code", required: true})),
				div({class: "my-2"}, input({type: "submit", value: "Verify"}))
			);
		} else if (status.val === "complete") {
			return div(
				{class: "my-8"},
				div("2FA setup completed"),
				button({class: "btn", onclick: () => (status.val = "start")}, "Re-setup 2FA")
			);
		}
	}

	return div(
		{class: "my-8 border rounded-lg p-2 relative"},
		() => (loading.val ? LoadingIndicator() : div()),
		flow,
		div({class: "mx-2 my-8"}, span(message))
	);
}

function Account() {
	const token = sessionStorage.getItem("token");
	const user = van.state(null);
	const loading = van.state(false);

	const changePasswordFormOpen = van.state(false);

	if (!token) {
		window.location.href = "/login";
	} else {
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

	return div(
		{class: "p-5"},
		h1("account"),
		Menu(),
		() => (loading.val ? LoadingIndicator() : div()),
		div(
			{class: "flex flex-row"},
			button(
				{
					class: "block my-4 px-4 cursor-pointer text-xl",
					role: "button",
					title: "Expand form",
					onclick: () => (changePasswordFormOpen.val = !changePasswordFormOpen.val),
				},
				() => (changePasswordFormOpen.val ? "-" : "+")
			),
			h2("Change password")
		),
		() => (user.val && changePasswordFormOpen.val ? ChangePassword() : div()),
		() => (user.val ? TOTPSetup(user.val.totp_setup) : div())
	);
}

document.addEventListener("DOMContentLoaded", () => {
	van.add(document.body, Account());
});
