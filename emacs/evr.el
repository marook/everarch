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

(require 'helm)
(require 'templar)
(require 'subr-x)

(setq evr--claim-ref-pattern "sha[0-9]+-224-\\([0-9a-z]\\)\\{56\\}-\\([0-9a-f]\\)\\{4\\}")

;;;###autoload
(defun evr-attr-index-search (query)
  "evr-search performs a search against the default
evr-attr-index and prints the results into a new buffer."
  (interactive "sQuery: ")
  (switch-to-buffer
   (generate-new-buffer
    (if (string-empty-p query)
        "every"
      query)))
  (insert query "\n")
  (evr-attr-index-results-mode)
  (evr-attr-index-search-from-buffer))

(defun evr-attr-index-search-from-buffer ()
  (interactive)
  (let ((ro inhibit-read-only))
    (goto-char (point-min))
    (forward-line (1- 2))
    (setq inhibit-read-only t)
    (delete-region (point) (point-max))
    (setq inhibit-read-only ro))
  (let ((query (buffer-substring-no-properties
                (point-min)
                (progn
                  (goto-char (point-min))
                  (end-of-line)
                  (point))))
        (con (open-network-stream
              "evr-attr-index-search"
              (buffer-name)
              "localhost" 2362
              :type 'tls)))
    (set-process-sentinel
     con
     (lambda (con event)
       ;; prevent process status from being printed to the search
       ;; results buffer
       nil))
    (process-send-string
     con
     (concat
      "a token " (cdr (assoc-string "localhost:2362" evr-attr-index-authentication-tokens)) "\n"
      (mapconcat
       (lambda (args)
         (apply 'concat args))
       `(
         ("s select *")
         ,(if (string-empty-p query)
              ()
            `("where " ,query)))
       " ")
      "\nexit\n"))))

(defvar evr-attr-index-authentication-tokens
  ()
  "Assoc list of authentication tokens. Keys are HOST:PORT
  strings. Values are authentication tokens.")

(defvar evr-attr-index-results-mode-map
  (let ((map (make-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map "p" 'evr-previous-claim-ref)
    (define-key map " " 'evr-next-claim-ref)
    (define-key map "n" 'evr-next-claim-ref)
    (define-key map "C" 'kill-current-buffer)
    (define-key map "r" 'isearch-backward)
    (define-key map "s" 'isearch-forward)
    (define-key map "g" 'evr-attr-index-search-from-buffer)
    (define-key map "x" 'evr-follow-claim-ref-xml)
    (define-key map "\C-m" 'evr-follow-claim-ref-search)
    (define-key map "c" 'evr-compose-claim-set-for-seed)
    (define-key map "f" 'evr-follow-claim-ref-contents)
    map)
  "Local keymap for evr-attr-index-results-mode buffers.")

(defun evr-previous-claim-ref ()
  (interactive)
  (re-search-backward evr--claim-ref-pattern nil t))

(defun evr-next-claim-ref ()
  (interactive)
  (let ((point-before (point)))
    (unless (eobp)
      (forward-char 1))
    (if (eq (re-search-forward evr--claim-ref-pattern nil t) nil)
        (goto-char point-before)
      (re-search-backward evr--claim-ref-pattern))))

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

(defun evr--remove-buffer (buffer-name)
  "Kills a buffer if it exists and asks if it is modified.

Returns t if no such buffer exists or it was successfully
killed. Returns nil otherwise."
  (if (get-buffer buffer-name)
      (with-current-buffer buffer-name
        (if (buffer-modified-p)
            (kill-buffer-ask (get-buffer buffer-name))
          (kill-buffer)))
    t))

(defun evr--visit-claim-xml (claim-ref seed-ref &optional complete)
  "Visit claim XML with given claim ref in a buffer.

Returns the buffer's name."
  (if (evr--remove-buffer claim-ref)
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
                 (if complete
                     (funcall complete claim-ref))
                 )))
         :stderr (get-buffer-create "*evr get-claim errors*")
         )
        claim-ref)))

(defun evr--follow-file-claim (claim-ref seed-ref buffer-name)
  (message "evr get %s" buffer-name)
  (if (evr--remove-buffer buffer-name)
      (make-process
       :name (concat "evr get-file " claim-ref)
       :buffer buffer-name
       :command `("evr" "get-file" ,claim-ref)
       :sentinel
       (lambda (process event)
         (if (string= event "finished\n")
             (with-current-buffer buffer-name
               (set-buffer-modified-p nil)
               (goto-char (point-min))
               (normal-mode)
               (setq-local evr-seed-ref seed-ref)
               (setq-local evr-claim-ref claim-ref)
               (evr-file-claim-mode nil)
               (switch-to-buffer buffer-name)
               )))
       :stderr (get-buffer-create "*evr get-file errors*")
       )))

(defun evr-follow-claim-ref-xml ()
  "Follows the claim ref at point and will show it's claim XML in
a new buffer."
  (interactive)
  (let ((buffer-name (evr--visit-claim-xml (evr--get-claim-ref) (evr--get-seed-ref))))
    (if buffer-name
        (switch-to-buffer buffer-name))))

(defun evr-follow-claim-ref-search ()
  "Follows the claim ref at point and will show it's attributes
in a new buffer."
  (interactive)
  (evr-attr-index-search (concat "ref=" (evr--get-claim-ref))))

(defun evr-compose-claim-set-for-seed ()
  (interactive)
  (let ((seed-ref (evr--get-seed-ref))
        (claim-set-buf (evr-compose-claim-set)))
    (with-current-buffer claim-set-buf
      (setq-local evr-seed-ref seed-ref))))

(defun evr-follow-claim-ref-contents ()
  "Follows the claim ref at point.

Will show the file contents in a new buffer if the claim ref
points to a file claim."
  (interactive)
  (evr--visit-claim-xml
   (evr--get-claim-ref)
   (evr--get-seed-ref)
   (lambda (buffer-name)
     (evr-follow-claim buffer-name))))

(defun evr-follow-claim (claim-buffer)
  "Follows the root claim within the current buffer."
  (interactive "bClaim: ")
  (with-current-buffer claim-buffer
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
        (message "No idea how to follow the claim in buffer %s" (buffer-name)))
      )))

(define-minor-mode evr-file-claim-mode
  "This minor mode makes a buffer an everarch sourced file."
  :init-value nil
  :group 'evr
  :lighter " evr-file-claim"
  (if evr-file-claim-mode
      (evr--enable-file-claim-mode)
    (evr--disable-file-claim-mode)))

(defun evr--enable-file-claim-mode ()
  (add-hook 'write-contents-functions 'evr-save-file nil t))

(defun evr--disable-file-claim-mode ()
  (remove-hook 'write-contents-functions 'evr-save-file t))

(defcustom evr-seed-file-claim-saved-hook nil
  "Run after `evr-save-file' saved a seed file claim.

The claim's seed and claim ref are passed as arguments. The seed
ref is always nil.

(add-hook
 'evr-seed-file-claim-saved-hook
 (lambda (seed-ref claim-ref)
   …
))
"
  :group 'evr
  :type 'hook)

(defcustom evr-file-claim-saved-hook nil
  "Run after `evr-save-file' saved a file claim.

The claim's seed and claim ref are passed as arguments.

(add-hook
 'evr-file-claim-saved-hook
 (lambda (seed-ref claim-ref)
   …
))
"
  :group 'evr
  :type 'hook)

;;;###autoload
(defun evr-save-file ()
  "Saves the current buffer as file in everarch.

Returns t if the claim-set was successfully saved."
  (interactive)
  (let ((file-buffer-name (buffer-name))
        (seed-ref (if (local-variable-p 'evr-seed-ref) evr-seed-ref)))
    (message "Saving evr file %s..." file-buffer-name)
    (let ((proc (make-process
                 :name (concat "evr post-file " file-buffer-name)
                 :buffer (get-buffer-create "*evr post-file errors*")
                 :command
                 (nconc
                  `("evr" "post-file" "--title" ,file-buffer-name)
                  (if seed-ref
                      `("--seed" ,seed-ref)
                    ()))
                 :filter
                 (lambda (proc out)
                   (with-current-buffer file-buffer-name
                     (setq-local evr-claim-ref (string-trim out))
                     (if (not seed-ref)
                         (setq-local evr-seed-ref evr-claim-ref))
                     (evr-file-claim-mode t)
                     (set-buffer-modified-p nil)
                     (if (not seed-ref)
                         (mapc
                          (lambda (hook)
                            (funcall hook nil evr-claim-ref))
                          evr-seed-file-claim-saved-hook))
                     (mapc
                      (lambda (hook)
                        (funcall hook evr-seed-ref evr-claim-ref))
                      evr-file-claim-saved-hook))
                   (message "Wrote %s" file-buffer-name)
                   nil)
                 :stderr (get-buffer-create "*evr post-file errors*")
                 )))
      (process-send-region proc (point-min) (point-max))
      (process-send-eof proc)
      ))
  t)

(defcustom evr-default-claim-set-xmlns-list
  '(
    (nil "https://evr.ma300k.de/claims/")
    ("dc" "http://purl.org/dc/terms/")
    )
  "List of default xml namespace declarations which are added to
composed claim-sets."
  :group 'evr)

(defun evr-put-seed-attr ()
  "evr-put-seed-attr returns a seed attribute like
  seed=\"sha3-224-…\" at point if the (usually buffer local)
  variable evr-seed-ref is defined.

This function is expected to be used with templar templates."
  (lambda (vars)
    (if (boundp 'evr-seed-ref)
        (concat
         " seed=\""
         evr-seed-ref
         "\"")
      "")))

(defvar
  evr-claim-templates
  `(
    ("attr"
     (
      (;; vars
       ("key" ,(templar-ask-for-value "my-key"))
       ("value" ,(templar-ask-for-value "some value"))
       )
      (;; template
       "<attr" ,(evr-put-seed-attr) ">
  <a op=\"=\" k=\"" ,(templar-put-var "key" 'identity) "\" v=\"" ,(templar-put-var "value" 'identity) "\"/>
</attr>"
       )
      )
     )
    )
  "evr-claim-templates references all templar templates which
produce claims.

Every template is a list of two items: (name template-spec)

name is the human readable name of the template.

template-spec is a list of two items: (var-specs template)

var-specs is a list of variables. Each variable is (name resover).")

(defun evr-insert-claim ()
  (interactive)
  (helm
   :sources
   (helm-build-sync-source
       "evr claims"
     :candidates evr-claim-templates
     :action
     `(
       ("Insert" . ,(lambda (template) (evr--insert-claim-at-point (car template))))
       ))))

(defun evr--insert-claim-at-point (template)
  (let ((claim-start-point (point))
        claim-end-point)
    (templar-insert-at-point template)
    (indent-region claim-start-point (point))))

(define-minor-mode evr-claim-set-mode
  "This minor mode makes a buffer an everarch sourced claim-set.

Saving this buffer will put the claim-set into evr and close the
buffer afterwards."
  :init-value nil
  :group 'evr
  :lighter " evr-claim-set"
  :keymap
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "C-x w") 'evr-insert-claim)
    map)
  (if evr-claim-set-mode
      (evr--enable-claim-set-mode)
    (evr--disable-claim-set-mode)))

(defun evr--enable-claim-set-mode ()
  (add-hook 'write-contents-functions 'evr-save-claim-set nil t))

(defun evr--disable-claim-set-mode ()
  (remove-hook 'write-contents-functions 'evr-save-claim-set t))

;;;###autoload
;; (evr-compose-claim-set)
(defun evr-compose-claim-set ()
  "Creates a new buffer with a template claim-set for everarch."
  (interactive)
  (let ((buf (generate-new-buffer "claim-set")) cursor-pos)
        (switch-to-buffer buf)
        (insert "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<claim-set")
        (mapc
         (lambda (xmlns)
           (seq-let (abbrev ns) xmlns
             (insert "\n    xmlns")
             (if abbrev
                 (progn
                   (insert ":")
                   (insert abbrev)))
             (insert "=\"")
             (insert ns)
             (insert "\"")
             ))
         evr-default-claim-set-xmlns-list)
        (if (>= (length evr-default-claim-set-xmlns-list) 0)
            (insert "\n    "))
        (insert ">\n  ")
        (setq cursor-pos (point))
        (insert "\n</claim-set>")
        (goto-char cursor-pos)
        (nxml-mode)
        (evr-claim-set-mode t)
        buf
        ))

(defcustom evr-claim-set-saved-hook nil
  "Run after `evr-save-claim-set' saved a claim set.

The claim set's ref is passed as argument.

(add-hook
 'evr-claim-set-saved-hook
 (lambda (claim-set-ref)
   …
))
"
  :group 'evr
  :type 'hook)

;;;###autoload
(defun evr-save-claim-set ()
  "Saves the current buffer as claim set into everarch.

Adds the current date and time as created attribute to the
claim-set if not present.

Returns t if the claim-set was successfully saved."
  (interactive)
  (let ((claim-set-buffer-name (buffer-name)))
    (evr-insert-claim-set-created-attr)
    (message "Saving evr claim set...")
    (let ((proc (make-process
                 :name (concat "evr sign-put " claim-set-buffer-name)
                 :buffer (get-buffer-create "*evr put claim-set errors*")
                 :command `("evr" "sign-put" "--flags" "1")
                 :filter
                 (lambda (proc out)
                   (with-current-buffer claim-set-buffer-name
                     (let ((claim-set-ref (string-trim out)))
                       (set-buffer-modified-p nil)
                       (mapc
                        (lambda (hook)
                          (funcall hook claim-set-ref))
                        evr-claim-set-saved-hook)
                       (message "Wrote claim-set %s" claim-set-ref)
                       (kill-buffer claim-set-buffer-name)))
                   nil)
                 :stderr (get-buffer-create "*evr put claim-set errors*")
                 )))
      (process-send-region proc (point-min) (point-max))
      (process-send-eof proc)
      ))
  t)

(defun evr-insert-claim-set-created-attr ()
  (goto-char (point-min))
  (unless (re-search-forward "<claim-set[ >\n\t]" nil t)
    (error "No claim-set element found."))
  ;; TODO lookup dc namespace abbrev in evr-default-claim-set-xmlns-list
  (let ((claim-set-attr-point (point))
        (claim-set-attr-end-point (re-search-forward ">" nil t))
        dc-created-point)
    (goto-char claim-set-attr-point)
    (setq dc-created-point (re-search-forward "dc:created[ =\n\t]" nil t))
    (when (or
           (not dc-created-point)
           (< claim-set-attr-end-point dc-created-point))
      (goto-char claim-set-attr-point)
      (backward-char 1)
      (insert " dc:created=\"")
      (insert (format-time-string "%FT%T.%3N000Z" nil "UTC0"))
      (insert "\""))
    ))

(provide 'evr)
