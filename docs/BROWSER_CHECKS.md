# Working browser verification

The application was exercised locally on macOS with Python 3.12, through the actual browser UI and fictional demo data. These screenshots show the working product, not generated mockups.

- Replayed 15 fictional authentication events: three explainable signals appeared.
- Annotated the burst as expected activity with an investigator note and revision 1.
- Replayed and exported again: the note remained; evidence displayed in chronological order.

All six apps were checked at a 390×844 viewport; this app's document width was 390px with no horizontal overflow. The temporary viewport was reset after the check. The fresh final app load reported no JavaScript errors. Desktop and mobile captures can show different points in the walkthrough.

Automated regression suite: **56 passing tests**. The README describes test scope and measured coverage. These checks do not establish production scale or complete security coverage.
