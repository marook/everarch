;; -*- lexical-binding: t -*-
;;
;; templar.el is a templating library for emacs.
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

(require 's)

(defvar
  templar-templates
  ()
  "templar-templas references all available templates. It should
be extended by the user.

Every template is a list of three items: (name match template-spec)

name is the human readable name of the template.

match is a match function without arguments which returns t if
the template is applicable in the current situation.

template-spec is a list of two items: (var-specs template)

var-specs is a list of variables. Each variable is (name resover).")

;;;###autoload
(defun templar-insert-template ()
  (interactive)
  (helm
   :sources
   (helm-build-sync-source
       "templar templates"
       :candidates
       (templar--find-templates-for-point templar-templates)
       :candidate-transformer
       (lambda (candidates)
         (mapcar
          (lambda (candidate)
            candidate)
          candidates))
       :action
       `(
         ("Insert" . ,(lambda (x)
                        (templar-insert-at-point (car x))))
         ))))

;; (templar--find-templates-for-point)
(defun templar--find-templates-for-point (templates)
  (mapcar
   (lambda (template-spec)
     (seq-let (name match template) template-spec
       `(,name ,template)
       ))
   (seq-filter
    (lambda (template-spec)
      (seq-let (name match template) template-spec
        (funcall match)))
    templates)))

;;;###autoload
(defun templar-insert-at-point (template-spec)
  "templar-insert-at-point renders and inserts the given
template-spec at point."
  (seq-let (var-specs template) template-spec
    (insert
     (let ((vars (templar--resolve-var-specs var-specs)))
       (templar--render vars template)))))

(defun templar--resolve-var-specs (var-specs)
  (mapcar
   (lambda (var-spec)
     (seq-let (key resolver) var-spec
       `(,key . ,(funcall resolver key))))
   var-specs))

(defun templar--render (vars template)
  (cond
   ((stringp template)
    template)
   ((functionp template)
    (templar--render vars (funcall template vars)))
   ((listp template)
    (apply
     'concat
     (mapcar
      (lambda (token)
        (templar--render vars token))
      template)))
   (t
    (error "Unknown template: %s" template))))

(defun templar-ask-for-value (example-val)
  (lambda (key)
    (read-string (concat key " [" example-val "]: "))))

(defun templar-ask-yes-no ()
  (lambda (key)
    (let ((c (read-char (concat key " [N,y,0,1]: "))))
      (if (or (= c ?0) (= c ?n) (= c ?N) (= c 13))
          nil
        t))))

(defun templar-put-var (key modifier)
  (lambda (vars)
    (let ((var (assoc-string key vars)))
      (if var
          (funcall modifier (cdr var))
        (error "No templar variable with name '%s' exists" key)))))

(defun templar-if (key predicate body)
  (lambda (vars)
    (let ((var (assoc-string key vars)))
      (if var
          (if (funcall predicate (cdr var))
              body)
        (error "No templar variable with name '%s' exists" key)))))

(provide 'templar)
