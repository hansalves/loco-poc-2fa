import van from "/js/van/van.js";
import Spinner from "/js/components/spinner.js";

const {div} = van.tags;

export default function LoadingIndicator(variant) {
	let variantClasses = "fixed top-0 left-0 w-full h-full z-50";
	if (variant === "absolute") {
		variantClasses = "absolute top-0 left-0 right-0 bottom-0";
	}
	return div({class: `${variantClasses} flex justify-center items-center bg-black opacity-50`},
		Spinner("large", "blue")
	);
}