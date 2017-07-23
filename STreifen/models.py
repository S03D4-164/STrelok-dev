from django.db import models

class STIXObjectType(models.Model):
    name = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class STIXObjectID(models.Model):
    object_id = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.object_id
    class Meta:
        ordering = ["object_id"]

class RelationshipType(models.Model):
    name = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class DefinedRelationship(models.Model):
    type = models.ForeignKey(RelationshipType)
    source = models.ForeignKey(STIXObjectType, related_name='source')
    target = models.ForeignKey(STIXObjectType, related_name='target')
    def __str__(self):
        drs = self.source.name + " " + self.type.name + " " + self.target.name
        return drs
    class Meta:
        unique_together = (("source", "type", "target"),)
        ordering = ["source", "type", "target"]

class STIXObject(models.Model):
    object_type = models.ForeignKey(STIXObjectType, blank=True, null=True)
    object_id = models.OneToOneField(STIXObjectID, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    created_by_ref = models.ForeignKey(STIXObjectID, related_name="createdby_ref", blank=True, null=True)
    #object_marking_refs = models.ManyToManyField(STIXObjectID, blank=True)
    class Meta:
        unique_together = (("object_type", "object_id"),)
        ordering = ["object_type", "object_id"]
    def delete(self):
        STIXObjectID.objects.get(object_id=self.object_id).delete()
    def __str__(self):
        return self.object_id.object_id

class MarkingDefinition(STIXObject):
    DEFINITION_TYPE_CHOICES = {
        ('statement','statement'),
        ('tlp','tlp'),
    }
    #object_marking_refs = models.ManyToManyField(STIXObjectID)
    definition_type = models.CharField(max_length=250, choices=DEFINITION_TYPE_CHOICES)
    definition =  models.CharField(max_length=250)
    class Meta:
        unique_together = (("definition_type", "definition"),)
        ordering = ["definition_type", "definition"]
    def __str__(self):
        return ":".join([definition_type,definition])

class ReportLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

def _set_id(obj, name):
    from uuid import uuid4
    if not obj.object_type:
        s = STIXObjectType.objects.filter(name=name)
        if s.count() == 1:
            obj.object_type = STIXObjectType.objects.get(name=name)
    if obj.object_type and not obj.object_id:
        soi = STIXObjectID.objects.create(
            object_id = obj.object_type.name + "--" + str(uuid4())
        )
        obj.object_id = soi
    return obj

class Report(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    labels = models.ManyToManyField(ReportLabel, blank=True)
    description = models.TextField(blank=True, null=True)
    published = models.DateTimeField(blank=True, null=True)
    object_refs = models.ManyToManyField(STIXObjectID, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'report')
        super(Report, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class IdentityLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    category = models.CharField(max_length=250, blank=True, null=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class IndustrySector(models.Model):
    value = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class Identity(STIXObject):
    IDENTITY_CLASS_CHOICES = {
        ('individual','individual'),
        ('group','group'),
        ('organization','organization'),
        ('class','class'),
        ('unknown','unknown'),
    }
    name = models.CharField(max_length=250,unique=True)
    identity_class = models.CharField(max_length=250, choices=IDENTITY_CLASS_CHOICES)
    #identity_class = models.ForeignKey(IdentityClass, blank=True)
    description = models.TextField(blank=True, null=True)
    sectors = models.ManyToManyField(IndustrySector, blank=True)
    labels = models.ManyToManyField(IdentityLabel, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'identity')
        super(Identity, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class AttackPattern(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    #external_references = models.ManyToManyField(ExternalReference, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'attack-pattern')
        super(AttackPattern, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ToolLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class Tool(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    labels = models.ManyToManyField(ToolLabel, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'tool')
        super(Tool, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class MalwareLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class Malware(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    labels = models.ManyToManyField(MalwareLabel, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'malware')
        super(Malware, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ThreatActorLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class ThreatActorAlias(models.Model):
    name = models.CharField(max_length=250, unique=True, blank=False)
    description = models.TextField(blank=True, null=True)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ThreatActor(STIXObject):
    name = models.CharField(max_length=250, unique=True, blank=False)
    description = models.TextField(blank=True, null=True)
    labels = models.ManyToManyField(ThreatActorLabel, blank=True)
    aliases = models.ManyToManyField(ThreatActorAlias, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'threat-actor')
        super(ThreatActor, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class Relationship(STIXObject):
    source_ref= models.ForeignKey(STIXObjectID, related_name='source_ref')
    target_ref = models.ForeignKey(STIXObjectID, related_name='target_ref')
    relationship_type = models.ForeignKey(RelationshipType)
    description = models.TextField(blank=True, null=True)
    def __str__(self):
        #src = self.source_ref.object_id
        #tgt = self.target_ref.object_id
        #rel = self.relationship_type.name
        #return " ".join([src, rel, tgt])
        return self.object_id.object_id
    def save(self, *args, **kwargs):
        self = _set_id(self, 'relationship')
        super(Relationship, self).save(*args, **kwargs)

class Sighting(STIXObject):
    sighting_of_ref= models.ForeignKey(STIXObjectID, related_name='sighting_of_ref')
    where_sighted_refs = models.ManyToManyField(STIXObjectID, related_name='where_sighted_ref')
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField(blank=True, null=True)
    #observed_data_refs = models.ManyToManyField(STIXObjectID, related_name='observed_data_refs')
    description = models.TextField(blank=True, null=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'sighting')
        super(Sighting, self).save(*args, **kwargs)
    def __str__(self):
        return self.object_id.object_id

class IndicatorLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class ObservableObjectType(models.Model):
    name = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ObservablePropertyName(models.Model):
    type = models.ForeignKey(ObservableObjectType)
    name = models.CharField(max_length=250)
    alias = models.CharField(max_length=250, unique=True, blank=True, null=True)
    class Meta:
        unique_together = (("type", "name"),)
        ordering = ["type", "name"]
    def __str__(self):
        return self.type.name + ":" + self.name

class ObservableProperty(models.Model):
    key = models.ForeignKey(ObservablePropertyName)
    value = models.CharField(max_length=25000)
    """
    key = models.CharField(max_length=250)
    class Meta:
        unique_together = (("type", "name"),)
        ordering = ["type", "name"]
    """
    def __str__(self):
        return self.key.type.name + ":" + self.key.name + "=" + self.value
    class Meta:
        ordering = ["key", "value"]

class ObservableObject(models.Model):
    type = models.ForeignKey(ObservableObjectType)
    property = models.ManyToManyField(ObservableProperty)
    description = models.TextField(blank=True, null=True)
    def __str__(self):
        v = []
        for p in self.property.all():
            v.append(p.value)
        return "/".join(v)

class IndicatorPattern(models.Model):
    observable = models.ManyToManyField(ObservableObject)
    pattern = models.TextField(blank=True, null=True)
    """
    property = models.ForeignKey(ObservableObjectProperty)
    value = models.CharField(max_length=25000)
    def __str__(self):
        o = self.property.type.name + ":" + self.property.name
        o += "=" + self.value
        return o
    class Meta:
        unique_together = (("property", "value"),)
        ordering = ["property", "value"]

    """

class Indicator(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    labels = models.ManyToManyField(IndicatorLabel)
    valid_from = models.DateTimeField(blank=True, null=True)
    valid_until = models.DateTimeField(blank=True, null=True)
    pattern = models.ManyToManyField(IndicatorPattern)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'indicator')
        super(Indicator, self).save(*args, **kwargs)

class CampaignAlias(models.Model):
    name = models.CharField(max_length=250, unique=True, blank=False)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class Campaign(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    #labels = models.ManyToManyField(IndicatorLabel)
    aliases = models.ManyToManyField(CampaignAlias, blank=True)
    first_seen = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'campaign')
        super(Campaign, self).save(*args, **kwargs)

class TaxiiCollection(models.Model):
    collection_id = models.CharField(max_length=250, unique=True, blank=True, null=True)
    title = models.CharField(max_length=250, unique=True, blank=False, null=False)
    description = models.TextField(blank=True, null=True)
    can_read = models.BooleanField(default=True)
    can_write = models.BooleanField(default=False)
    stix_objects = models.ManyToManyField(STIXObject)
    def save(self, *args, **kwargs):
        if not self.collection_id:
            from uuid import uuid4
            self.collection_id = str(uuid4()) 
        super(TaxiiCollection, self).save(*args, **kwargs)
