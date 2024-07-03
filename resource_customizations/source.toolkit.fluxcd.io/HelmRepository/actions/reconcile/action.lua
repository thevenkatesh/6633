local os = require("os")
if obj.metadata.annotations == nil then
    obj.metadata.annotations = {}
end
obj.metadata.annotations["reconcile.fluxcd.io/requestedAt"] = "By ArgoCD at: " .. os.date("!%Y-%m-%dT%X")

return obj
