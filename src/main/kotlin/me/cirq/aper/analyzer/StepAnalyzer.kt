package me.cirq.aper.analyzer

import me.cirq.aper.analyzer.report.RevStepReport
import me.cirq.aper.analyzer.report.StepReport
import me.cirq.aper.analyzer.step.CheckStep
import me.cirq.aper.analyzer.step.DeclareStep
import me.cirq.aper.analyzer.step.HandleStep
import me.cirq.aper.analyzer.step.RequestStep
import me.cirq.aper.entity.DCallChain
import me.cirq.aper.util.LogUtil


object StepAnalyzer {

    /**
     * find all dangerous call chains, with step checking
     */
    fun analyze(callchains: Set<DCallChain>, dump: Boolean=false): Set<StepReport> {
        return callchains.withIndex().map { (i, chain) ->
            val report = stepPipeline(chain)
            LogUtil.info(this, "generate report of ${i+1}-${report.api}")
            if(dump) {
                val file = report.dump()
                LogUtil.debug(this, "write report file to $file")
            }
            report
        }.toHashSet()
    }

    private fun stepPipeline(chain: DCallChain): StepReport {
        val report = StepReport(chain)

        val step1result = DeclareStep.isPermissionDeclared(chain.permissions)
        report.addDeclareResult(step1result)

        val step2result = CheckStep.findAllChecksites(chain)
        report.addCheckResult(step2result)

        val step3result = RequestStep.findAllRequestsites(chain)
        report.addRequestResult(step3result)

        val step4result = HandleStep.findHandleCallbacks(chain)
        report.addHandleResult(step4result)

        // todo: the last step

        step1result.forEach{ (p, dec) ->
            LogUtil.debug(this, "Permission {} declared={} with {}-CHECK/{}-REQUEST/{}-HANDLE",
                    p, dec, step2result[p]!!.size, step3result[p]!!.size, step4result[p]!!.size)
        }
        return report
    }

    /**
     * find all permission maintaining chains, foucus on step check&request
     */
    fun reverseAnalyze(dump: Boolean=false): RevStepReport {
        val revReport = RevStepReport()

        val checkResult = CheckStep.getCheckCallchains()
        val cresult = revReport.addCheckResult(checkResult)
        LogUtil.info(this, "Collect {} CHECK chains", checkResult.size)
        if(dump) {
            cresult.dump().forEach {
                LogUtil.debug(this, "write CHECK rev-report file to $it")
            }
        }

        val requestResult = RequestStep.getRequestCallchains()
        val rresult = revReport.addRequestResult(requestResult)
        LogUtil.info(this, "Collect {} REQUEST chains", requestResult.size)
        if(dump) {
            rresult.dump().forEach {
                LogUtil.debug(this, "write REQUEST rev-report file to $it")
            }
        }

        return revReport
    }

}
