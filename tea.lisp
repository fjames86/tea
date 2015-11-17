;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; Implements XXTEA encryption. 
;;; Input data octets are converted to big-endian integers. If the other recipient is using
;;; little-endian conversion then you'll need to swap the input data octets around to cancel this out.
;;;
;;; Usage is pretty straightforward:
;;; (let ((key '(1 2 3 4))
;;;       (v (make-array 24 :initial-element 12)))
;;;     (tea:encrypt key v)
;;;     (tea:decrypt key v))
;;; 

(defpackage #:tea 
  (:use #:cl)
  (:export #:encrypt
           #:decrypt
           #:generate-key
           #:key-octets
           #:octets-key))

(in-package #:tea)

(defun generate-key ()
  "Generate a random TEA key, which is just a list of 4 \(UNSIGNED-BYTE 32\) integers."
  (loop :for i :below 4 :collect (random #.(expt 2 32))))

(defconstant +delta+ #x9e3779b9)

(declaim (ftype (function ((unsigned-byte 32)
                           (unsigned-byte 32))
                          (unsigned-byte 32))
                mod-sub32))
(defun mod-sub32 (a b)
  (declare (type (unsigned-byte 32) a b))
  (cond
    ((> a b)
     (the (unsigned-byte 32) (- a b)))
    ((= a b) 0)
    (t 
     (the (unsigned-byte 32) (+ #.(expt 2 32) (- a b))))))

(declaim (ftype (function ((unsigned-byte 32)
                           (unsigned-byte 32))
                          (unsigned-byte 32))
                mod-add32))
(defun mod-add32 (a b)
  (declare (type (unsigned-byte 32) a b))
  (the (unsigned-byte 32) (mod (+ a b) #.(expt 2 32))))

(defun encrypt (key sequence &key (start 0) end)
  "Encrypt the data using XXTEA.

KEY ::= sequence of 4 integers \(UNSIGNED-BYTE 32\).
SEQUENCE ::= sequence of octets \(UNSIGNED-BYTE 8\).

START, END ::= usual start and end positions.

The SEQUENCE is modified and replaced with the encrypted version.

Returns SEQUENCE."
  (let ((count (- (or end (length sequence)) start)))
    (unless (zerop (mod count 4))
      (error "sequence length must be multiple of 4"))
    ;; convert the octet vector data into vector of be-uint32s 
    (let* ((n (truncate count 4))
           (v (make-array n :element-type '(unsigned-byte 32))))
      (declare (type (vector (unsigned-byte 32)) v))
      
      (dotimes (i n)
        (setf (aref v i)
              (logior (ash (elt sequence (+ start (* 4 i))) 24)
                      (ash (elt sequence (+ start (* 4 i) 1)) 16)
                      (ash (elt sequence (+ start (* 4 i) 2)) 8)
                      (elt sequence (+ start (* 4 i) 3)))))
      
      (do ((rounds (+ 6 (truncate 52 n)) (1- rounds))
           (sum 0)
           (z (aref v (1- n)))
           (e 0))
          ((zerop rounds))
        (declare (type (unsigned-byte 32) rounds sum z e))
        (setf sum 
              (mod-add32 sum +delta+)
              e 
              (logand (ash sum -2) 3))
        
        (dotimes (p (1- n))
          (let ((y (aref v (1+ p))))
            (declare (type (unsigned-byte 32) y))
            (setf (aref v p)
                  (mod-add32 
                   (aref v p)
                   (logand (logxor (+ (logxor (ash z -5) (ash y 2))
                                      (logxor (ash y -3) (ash z 4)))
                                   (+ (logxor sum y)
                                      (logxor (elt key (logxor (logand p 3) e))
                                              z)))
                           #xffffffff))
                  z (aref v p))))
        (let ((y (aref v 0)))
          (declare (type (unsigned-byte 32) y))
          (setf (aref v (1- n))
                (mod-add32 
                 (aref v (1- n))
                 (logand (logxor (+ (logxor (ash z -5) (ash y 2))
                                    (logxor (ash y -3) (ash z 4)))
                                 (+ (logxor sum y)
                                    (logxor (elt key (logxor (logand (1- n) 3) e))
                                            z)))
                         #xffffffff))
                z 
                (aref v (1- n)))))
      
      ;; convert back from integers to octets
      (dotimes (i n)
        (let ((x (aref v i)))
          (setf (elt sequence (+ start (* 4 i))) (logand (ash x -24) #xff)
                (elt sequence (+ start (* 4 i) 1)) (logand (ash x -16) #xff)
                (elt sequence (+ start (* 4 i) 2)) (logand (ash x -8) #xff)
                (elt sequence (+ start (* 4 i) 3)) (logand x #xff))))

      sequence)))

(defun decrypt (key sequence &key (start 0) end)
  "Decrypt the sequence using XXTEA. 

KEY ::= sequence of 4 integers \(UNSIGNED-BYTE 32\).
SEQUENCE ::= sequence of octets \(UNSIGNED-BYTE 8\).

START, END ::= usual start and end positions.

The SEQUENCE is modified and replaced with the decrypted version.

Returns SEQUENCE."

  (let ((count (- (or end (length sequence)) start)))
    (unless (zerop (mod count 4))
      (error "sequence length must be multiple of 4"))
    ;; convert the octet vector data into vector of be-uint32s 
    (let* ((n (truncate count 4))
           (v (make-array n :element-type '(unsigned-byte 32))))
      (declare (type (vector (unsigned-byte 32)) v))

      ;; convert from octets to integers
      (dotimes (i n)
        (setf (aref v i)
              (logior (ash (elt sequence (+ start (* 4 i))) 24)
                      (ash (elt sequence (+ start (* 4 i) 1)) 16)
                      (ash (elt sequence (+ start (* 4 i) 2)) 8)
                      (elt sequence (+ start (* 4 i) 3)))))
      
      (do ((rounds (+ 6 (truncate 52 n)) (1- rounds))
           (sum (logand (* (+ 6 (truncate 52 n)) +delta+) #xffffffff))
           (y (aref v 0))
           (z 0))
          ((zerop rounds))
        (declare (type (unsigned-byte 32) rounds sum y z))
        (let ((e (logand (ash sum -2) 3)))
          (declare (type (unsigned-byte 32) e))
          (do ((p (1- n) (1- p)))
              ((zerop p))
            (setf z (aref v (1- p)))
            (setf (aref v p)
                  (mod-sub32 
                   (aref v p)
                   (logand (logxor (+ (logxor (ash z -5) (ash y 2))
                                      (logxor (ash y -3) (ash z 4)))
                                   (+ (logxor sum y)
                                      (logxor (elt key (logxor (logand p 3) e))
                                              z)))
                           #xffffffff)))
            (setf y (aref v p)))
          (setf z (aref v (1- n)))
          (setf (aref v 0)
                (mod-sub32 
                 (aref v 0)
                 (logand (logxor (+ (logxor (ash z -5) (ash y 2))
                                    (logxor (ash y -3) (ash z 4)))
                                 (+ (logxor sum y)
                                    (logxor (elt key (logxor (logand 0 3) e))
                                            z)))
                         #xffffffff)))
          (setf y (aref v 0))
          (setf sum (mod-sub32 sum +delta+))))

      ;; convert back from integers to octets
      (dotimes (i n)
        (let ((x (aref v i)))
          (setf (elt sequence (+ start (* 4 i))) (logand (ash x -24) #xff)
                (elt sequence (+ start (* 4 i) 1)) (logand (ash x -16) #xff)
                (elt sequence (+ start (* 4 i) 2)) (logand (ash x -8) #xff)
                (elt sequence (+ start (* 4 i) 3)) (logand x #xff))))

      sequence)))


(defun key-octets (key)
  (let ((v (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 4)
      (let ((x (elt key i)))
        (setf (aref v (* 4 i)) (logand (ash x -24) #xff)
              (aref v (+ (* 4 i) 1)) (logand (ash x -16) #xff)
              (aref v (+ (* 4 i) 2)) (logand (ash x -8) #xff)
              (aref v (+ (* 4 i) 3)) (logand x #xff))))
    v))

(defun octets-key (octets)
  (let ((key (list nil nil nil nil)))
    (dotimes (i 4)
      (setf (elt key i)
            (logior (ash (elt octets (+ (* 4 i))) 24)
                    (ash (elt octets (+ (* 4 i) 1)) 16)
                    (ash (elt octets (+ (* 4 i) 2)) 8)
                    (elt octets (+ (* 4 i) 3)))))
    key))
      

    
(defun test1 ()
  (let ((key '(1 2 3 4))
        (v (make-array 24 :initial-element 12 :element-type '(unsigned-byte 8))))
    (unless (every #'=
                   #(201 28 13 105 246 74 92 235 34 84 29 249 222 155 170 193 162 235 214 104 133 87 102 168)
                   (encrypt key v))
      (error "Failed to encrypt"))
    (unless (every #'=
                   #(12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12)
                   (decrypt key v))
      (error "Failed to decrypt"))
    t))

  
        
