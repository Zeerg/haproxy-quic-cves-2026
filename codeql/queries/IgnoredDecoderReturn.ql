/**
 * @name Ignored result from a failable indirect-output operation
 * @description Finds ignored results from 0/1-returning functions that can update data through a pointer-to-pointer parameter.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/ignored-failable-indirect-output-result
 * @tags reliability
 *       security
 *       external/cwe/cwe-252
 */

import cpp

predicate hasBooleanStyleFailureContract(Function function) {
  exists(ReturnStmt failure, ReturnStmt success |
    failure.getEnclosingFunction() = function and
    failure.getExpr().getValue() = "0" and
    success.getEnclosingFunction() = function and
    success.getExpr().getValue() = "1"
  )
}

predicate hasIndirectOutputParameter(Function function) {
  exists(Parameter parameter, PointerType outer |
    parameter = function.getAParameter() and
    outer = parameter.getType().getUnspecifiedType() and
    outer.getBaseType().getUnspecifiedType() instanceof PointerType
  )
}

from FunctionCall call, Function target, ExprStmt statement
where
  statement.getExpr() = call and
  target = call.getTarget() and
  call.getType().getUnspecifiedType() instanceof IntegralType and
  hasBooleanStyleFailureContract(target) and
  hasIndirectOutputParameter(target)
select call, "The failure result of $@ is ignored even though the operation can update indirect output.",
  target, target.getName()
