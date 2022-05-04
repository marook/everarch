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

(setq evr--claim-ref-pattern "sha[0-9]+-224-\\([0-9a-z]\\)\\{56\\}-\\([0-9a-f]\\)\\{4\\}")

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
    (define-key map "f" 'evr-follow-claim-ref)
    (define-key map "\C-m" 'evr-follow-claim-ref)
    map)
  "Local keymap for evr-attr-index-results-mode buffers.")

(defface evr-claim-ref
  '((t (:inherit link)))
  "Face used for everarch claim refs."
  :group 'evr-faces
  :version "22.1")
(defvar evr-claim-ref-face 'evr-claim-ref
  "Face name used for everarch claim refs.")

(defface evr-claim-attribute
  '()
  "Face used for claim attributes."
  :group 'evr-faces
  :version "22.1")
(defvar evr-claim-attribute-face 'evr-claim-attribute
  "Face name used for claim attributes.")

(defvar evr-attr-index-results-font-lock-keywords
  (list
   (list evr--claim-ref-pattern '(0 evr-claim-ref-face))
   (list "[^\t=][^=]*=.*$" '(0 evr-claim-attribute-face))
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

(defun evr--goto-claim-ref-beginning ()
  (end-of-line)
  (re-search-backward evr--claim-ref-pattern))

(defun evr--get-claim-ref ()
  "Returns the claim reference at or before point."
  (save-excursion
    (evr--goto-claim-ref-beginning)
    (let ((start (point)))
      (end-of-line)
      (buffer-substring-no-properties start (point)))))

(defun evr--goto-seed-ref-beginning ()
  (end-of-line)
  (re-search-backward (concat "^" evr--claim-ref-pattern "$")))

(defun evr--get-seed-ref ()
  "Returns the seed reference at or before point."
  (save-excursion
    (evr--goto-seed-ref-beginning)
    (let ((start (point)))
      (end-of-line)
      (buffer-substring-no-properties start (point)))))

(defun evr-find-claim (claim-ref seed-ref)
  "Visit claim with given claim ref."
  (interactive "sRef: ")
  (let ((old-claim-buffer (get-buffer claim-ref)))
    (if old-claim-buffer (kill-buffer old-claim-buffer)))
  (let ((claim-ref-buffer (get-buffer-create claim-ref)))
    (make-process
     :name (concat "evr get-claim " claim-ref)
     :buffer claim-ref
     :command `("evr" "get-claim" ,claim-ref)
     :sentinel
     (lambda (process event)
       (if (string= event "finished\n")
           (with-current-buffer claim-ref-buffer
             (set-buffer-modified-p nil)
             (normal-mode)
             (setq-local evr-seed-ref seed-ref)
             (setq-local evr-claim-ref claim-ref)
             )))
     :stderr (get-buffer-create "*evr get-claim errors*")
     )
    (switch-to-buffer claim-ref)))

(defun evr-follow-claim ()
  "Follows the root claim within the current buffer."
  (interactive)
  (let ((claim-doc (libxml-parse-xml-region (point-min) (point-max))))
    ;; TODO add xml namespace handling here
    (if (string= (symbol-name (car claim-doc)) "file")
        (let ((file-attrs (car (cdr claim-doc)))
              (title evr-claim-ref))
          (if file-attrs
              (let ((title-attr-value (alist-get 'title file-attrs)))
                (if title-attr-value
                    (setq title title-attr-value))))
          (evr--follow-file-claim evr-claim-ref evr-seed-ref title))
      (message "No idea how to follow this claim"))
  ))

(defun evr--follow-file-claim (claim-ref seed-ref buffer-name)
  ;; TODO assert evr-claim-ref buffer local variable is set
  (message "evr get %s" buffer-name)
  (make-process
   :name (concat "evr get-file " claim-ref)
   :buffer buffer-name
   :command `("evr" "get-file" ,claim-ref)
   :sentinel
   (lambda (process event)
     (if (string= event "finished\n")
         (with-current-buffer buffer-name
           ;; TODO should we call set-visited-file-name?
           (set-buffer-modified-p nil)
           (goto-char (point-min))
           (normal-mode)
           (setq-local evr-seed-ref seed-ref)
           (setq-local evr-claim-ref claim-ref)
           (evr-file-claim-mode nil)
           (switch-to-buffer buffer-name)
           )))
   :stderr (get-buffer-create "*evr get-file errors*")
   ))

(defun evr-follow-claim-ref ()
  "Follows the claim ref at point."
  (interactive)
  nil
  (evr-find-claim (evr--get-claim-ref) (evr--get-seed-ref)))

(defun evr-file-claim-mode (&optional arg)
  "This minor mode makes a buffer an everarch sourced file."
  (interactive (list (or current-prefix-arg 'toggle)))
  (let ((enable
         (if (eq arg 'toggle)
             (not evr-file-claim-mode)
           (> (prefix-numeric-value arg) 0))))
    (if enable
        (evr-enable-file-claim-mode)
      (evr-disable-file-claim-mode))))

;;;###autoload
(defun evr-save-file ()
  "Saves the current buffer as file in everarch."
  (interactive)
  (let ((file-buffer-name (buffer-name)))
    (message "Saving evr file %s..." file-buffer-name)
    (let ((proc (make-process
                 :name (concat "evr post-file " file-buffer-name)
                 :buffer (get-buffer-create "*evr post-file errors*")
                 ;; TODO use buffer's file name instead of buffer-name
                 :command
                 (nconc
                  `("evr" "post-file" "--title" ,file-buffer-name)
                  (if (local-variable-p 'evr-seed-ref)
                      `("--seed" ,evr-seed-ref)
                    ()))
                 :filter
                 (lambda (proc out)
                   (with-current-buffer file-buffer-name
                     (if (not (local-variable-p 'evr-seed-ref))
                         (setq-local evr-seed-ref (string-trim out)))
                     (evr-file-claim-mode t)
                     (set-buffer-modified-p nil))
                   (message "Wrote %s" file-buffer-name)
                   nil)
                 :stderr (get-buffer-create "*evr post-file errors*")
                 )))
      (process-send-region proc (point-min) (point-max))
      (process-send-eof proc)
      ))
  t)

(defun evr-enable-file-claim-mode ()
  (add-hook 'write-contents-functions 'evr-save-file nil t))

(defun evr-disable-file-claim-mode ()
  (remove-hook 'write-contents-finctions 'evr-save-file t))
