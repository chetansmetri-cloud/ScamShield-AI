# User guide

## Create an account and sign in

Register from the landing page, then sign in to access the dashboard and
private investigation history. Sign out when finished on a shared device.
Account recovery by email is not configured.

## Investigate a website or job

Choose a website or offer investigation. Provide the exact public URL when
available; for a job, include the company, role, job ID, recruiter and offer
details. The app searches public sources and asks TinyFish Fetch to inspect the
submitted URL. Review submitted and final URLs, extracted listing details,
source attribution, matches, warnings and unknowns. A page match does not
authenticate an offer or recruiter.

## Screen documents, messages, QR codes and screenshots

- **Offer letter:** paste text or upload a text PDF, JPG, JPEG or PNG; review
  extracted claims and missing details.
- **Email:** paste a message or upload `.eml`; attachments are ignored. Link
  research is opt-in.
- **QR:** decode an image and inspect the destination. The app does not open a
  decoded destination automatically.
- **Screenshot:** upload an image for local OCR; compare the extracted text to
  the source image because OCR may misread content.

Uploads are limited to 8 MB; the batch CSV limit is 1 MB. Uploaded documents
and raw message contents are not retained by default. Some redacted reports
can be retained only after opting in.

## Batch checks and watchlist

Submit up to 10 URLs per batch, one per line or in a CSV. Each URL gets its own
result; failed URLs do not stop the rest. Export the batch summary to CSV.

Add a domain or organization to the watchlist. Scheduled checks are opt-in and
available at 6, 12, 24 or 168-hour intervals only while the background
scheduler is running. Use the manual check and check history controls as
needed. Monitoring pauses when the service stops; it is not a continuous
availability guarantee.

## Understand the report

The score counts configured warning indicators; it is not a probability of
fraud. “Insufficient evidence” means the available information cannot support
a low-risk conclusion. “Verified” observations, public allegations,
rule-based inferences and unknown information are shown separately. Follow the
recommended independent verification steps and never pay a fee or share OTPs,
passwords, or unnecessary financial/identity information based only on an
offer or a low score.

Reports are private to the signed-in account. Saved reports, history, analytics
and watchlists are user-scoped. PDF export is available for saved investigation
reports.
