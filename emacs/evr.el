;; -*- lexical-binding: t -*-
;;
;; evr.el is an emacs client for the everarch archive.
;; Copyright (C) 2022 Markus Peröbner
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Affero General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Affero General Public License for more details.
;;
;; You should have received a copy of the GNU Affero General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;;###autoload
(defun evr-attr-index-search (query)
  "evr-search performs a search against the default
evr-attr-index and prints the results into a new buffer."
  (interactive "sQuery: ")
  (switch-to-buffer (generate-new-buffer query))
  (insert query "\n")
  (evr-attr-index-results-mode)
  (evr-attr-index-search-from-buffer))

(defun evr--terminate-on-message-end-filter (proc string)
  (when (buffer-live-p (process-buffer proc))
    (with-current-buffer (process-buffer proc)
      (let ((moving (= (point) (process-mark proc)))
            (ro inhibit-read-only))
        (save-excursion
          ;; Insert the text, advancing the process marker.
          (goto-char (process-mark proc))
          (setq inhibit-read-only t)
          (insert string)
          (setq inhibit-read-only ro)
          (set-marker (process-mark proc) (point)))
        (if moving (goto-char (process-mark proc))))))
  (if (cl-search "\n\n" string)
      (delete-process proc)))

(defun evr-attr-index-search-from-buffer ()
  (interactive)
  (let ((ro inhibit-read-only))
    (goto-char (point-min))
    (forward-line (1- 2))
    (setq inhibit-read-only t)
    (delete-region (point) (point-max))
    (setq inhibit-read-only ro))
  (let ((query (buffer-substring
                (point-min)
                (progn
                  (goto-char (point-min))
                  (end-of-line)
                  (point))))
        (con (open-network-stream "evr-attr-index-search" (buffer-name) "localhost" 2362)))
    (set-process-filter con 'evr--terminate-on-message-end-filter)
    (process-send-string con (concat "s select * where " query "\n"))))

(defvar evr-attr-index-results-mode-map
  (let ((map (make-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map "C" 'kill-current-buffer)
    (define-key map "r" 'isearch-backward)
    (define-key map "s" 'isearch-forward)
    (define-key map "g" 'evr-attr-index-search-from-buffer)
    map)
  "Local keymap for evr-attr-index-results-mode buffers.")

(defface evr-claim-ref
  '((t (:inherit shadow)))
  "Face used for everarch claim refs."
  :group 'evr-faces
  :version "22.1")
(defvar evr-claim-ref-face 'evr-claim-ref
  "Face name used for everarch claim refs.")

(defface evr-claim-attribute-claim-ref
  '((t (:inherit link)))
  "Face used for claim attributes which reference claims."
  :group 'evr-faces
  :version "22.1")
(defvar evr-claim-attribute-claim-ref-face 'evr-claim-attribute-claim-ref
  "Face name used for claim attributes which reference claims.")

(defface evr-claim-attribute
  '()
  "Face used for claim attributes."
  :group 'evr-faces
  :version "22.1")
(defvar evr-claim-attribute-face 'evr-claim-attribute
  "Face name used for claim attributes.")

(defvar evr-attr-index-results-font-lock-keywords
  (list
   (list "^sha[0-9]+-[0-9]+-[a-z0-9]+-[a-f0-9]+$" '(0 evr-claim-ref-face))
   ;; TODO parameterize the following "file" key name
   (list "^\tfile=.*$" '(0 evr-claim-attribute-claim-ref-face))
   (list "^\t[^\t=][^=]*=.*$" '(0 evr-claim-attribute-face))
  ))

(defun evr-attr-index-results-mode ()
  "Mode for browsing evr-attr-index search results."
  (kill-all-local-variables)
  (use-local-map evr-attr-index-results-mode-map)
  (setq major-mode 'evr-attr-index-results-mode
        mode-name "evr-attr-index-results"
        buffer-read-only t)
  (setq-local tab-width 2)
  (setq-local font-lock-defaults
              '(evr-attr-index-results-font-lock-keywords t nil nil beginning-of-line))
  (font-lock-ensure)
  (run-mode-hooks 'evr-attr-index-results-mode-hook))
