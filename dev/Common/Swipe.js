/**
 * Recognises a horizontal one-finger swipe without taking anything away from the
 * element it watches.
 *
 * Touch only, deliberately. A pointer-events version would also fire for the
 * mouse, where dragging already means selecting text.
 *
 * Nothing is consumed until the gesture has proved itself horizontal and passed
 * `threshold`, so scrolling, tapping a link and holding to select all behave as
 * they did. `canStart` is asked once per gesture, which is what lets a container
 * that is scrolled sideways keep its own swipes.
 */
export const horizontalSwipe = (el, {
	// Whether to recognise anything at all right now.
	enabled = () => true,
	// Given the direction (-1 left, 1 right), may this become a navigation?
	canStart = () => true,
	// Live offset in pixels while the finger is down, 0 when abandoned.
	onMove = () => {},
	// Fired once, on release past the threshold.
	onCommit = () => {},
	// How far the finger must travel before the gesture commits.
	threshold = 60,
	// How much more horizontal than vertical the movement must be.
	ratio = 1.5
} = {}) => {
	let startX = 0,
		startY = 0,
		dx = 0,
		// null until the gesture has been judged, then true or false for its life.
		panning = null;

	const reset = () => {
			if (panning) {
				onMove(0);
			}
			panning = null;
			dx = 0;
		},

		start = e => {
			reset();
			// Ignore anything that is not a plain single-finger gesture, so
			// pinch to zoom is untouched.
			if (1 === e.touches.length && enabled()) {
				startX = e.touches[0].clientX;
				startY = e.touches[0].clientY;
			} else {
				startX = startY = 0;
			}
		},

		move = e => {
			if (!startX || 1 !== e.touches.length) {
				return;
			}
			dx = e.touches[0].clientX - startX;
			const dy = e.touches[0].clientY - startY;

			if (null === panning) {
				// Wait for enough movement to tell a swipe from a scroll or a tap.
				if (10 > Math.abs(dx) && 10 > Math.abs(dy)) {
					return;
				}
				panning = Math.abs(dx) > Math.abs(dy) * ratio && canStart(0 > dx ? -1 : 1);
			}

			if (panning) {
				// Only now, once it is certainly ours, is the scroll suppressed.
				e.cancelable && e.preventDefault();
				onMove(dx);
			}
		},

		end = () => {
			const committed = panning && Math.abs(dx) >= threshold,
				direction = 0 > dx ? -1 : 1;
			if (panning) {
				onMove(0);
			}
			panning = null;
			startX = 0;
			committed && onCommit(direction);
			dx = 0;
		};

	el.addEventListener('touchstart', start, {passive:true});
	// Not passive: this one may need to preventDefault once it owns the gesture.
	el.addEventListener('touchmove', move);
	el.addEventListener('touchend', end, {passive:true});
	el.addEventListener('touchcancel', reset, {passive:true});
};
