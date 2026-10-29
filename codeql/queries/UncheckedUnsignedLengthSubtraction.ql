/**
 * @name Range-unproven subtraction reaching a size or pointer use
 * @description Finds potentially unsafe subtraction that reaches a size_t argument or subtracts from a computed pointer offset.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/range-unproven-subtraction-to-size-or-pointer
 * @tags reliability
 *       security
 *       external/cwe/cwe-191
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis

bindingset[length, amount]
predicate mayUnderflow(Expr length, Expr amount) {
  length.getType().getUnspecifiedType().(IntegralType).isUnsigned() and
  lowerBound(length.getFullyConverted()) < upperBound(amount.getFullyConverted())
}

predicate isUnsignedSubtraction(Expr operation, Expr length, Expr amount) {
  exists(SubExpr subtraction |
    length = subtraction.getLeftOperand().getUnconverted() and
    amount = subtraction.getRightOperand().getUnconverted() and
    operation = subtraction
  )
}

predicate isPointerOffsetSubtraction(Expr operation, Expr length, Expr amount) {
  exists(PointerSubExpr pointerSubtraction, PointerAddExpr pointerAddition |
    pointerSubtraction.getLeftOperand().getUnconverted() = pointerAddition and
    length = pointerAddition.getRightOperand().getUnconverted() and
    amount = pointerSubtraction.getRightOperand().getUnconverted() and
    operation = pointerSubtraction
  )
}

predicate flowsToSizeArgument(Expr operation, Expr use) {
  exists(FunctionCall call, int index |
    use = call and
    call.getTarget().getParameter(index).getType().hasName("size_t") and
    DataFlow::localFlow(
      DataFlow::exprNode(operation), DataFlow::exprNode(call.getArgument(index))
    )
  )
}

predicate isPotentialUnderflow(Expr operation, Expr length, Expr amount, Expr use) {
  isUnsignedSubtraction(operation, length, amount) and flowsToSizeArgument(operation, use)
  or
  isPointerOffsetSubtraction(operation, length, amount) and use = operation
}

from Expr operation, Expr length, Expr amount, Expr use
where
  isPotentialUnderflow(operation, length, amount, use) and
  mayUnderflow(length, amount)
select use,
  "Subtraction is not proven safe because $@ may be smaller than $@.",
  length, length.toString(), amount, amount.toString()
