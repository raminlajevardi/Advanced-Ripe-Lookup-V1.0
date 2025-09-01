# GUI Modularization Notes

This refactor extracts each `create_*_tab` method from `gui/main_window.py`
into its own module under `gui/tabs/` while keeping behavior identical.
- Each module exports a function with the same name, e.g., `create_lookup_tab(app, ...)`.
- The `AdvancedRIPEIPLookup` class now delegates to these functions.
- Callbacks still reference `self` (passed as `app`), so existing logic remains intact.

## Why this approach?
- Minimal risk: business logic stays where it is.
- Clear separation: UI construction per tab is now isolated.
- Easier maintenance: You can open `gui/tabs/<tab>_tab.py` to work on a specific tab.

## How to add a new tab
1. Create a new module in `gui/tabs/newfeature_tab.py` with a function `create_newfeature_tab(app)`.
2. Import it at the top of `gui/main_window.py` (see the auto-generated import block).
3. Add a thin delegating method in `AdvancedRIPEIPLookup` if you prefer keeping a method entry point.

